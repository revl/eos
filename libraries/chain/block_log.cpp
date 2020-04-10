#include <eosio/chain/block_log.hpp>
#include <eosio/chain/exceptions.hpp>
#include <fstream>
#include <fc/bitutil.hpp>
#include <fc/io/cfile.hpp>
#include <fc/io/raw.hpp>
#include <boost/iostreams/device/mapped_file.hpp>
#include <boost/filesystem.hpp>
#include <variant>
#include <algorithm>
#include <variant>

#define LOG_WRITE_C "ab+"
#define LOG_RW_C "rb+"

namespace eosio { namespace chain {

   const uint32_t block_log::min_supported_version = 1;

   /**
    * History:
    * Version 1: complete block log from genesis
    * Version 2: adds optional partial block log, cannot be used for replay without snapshot
    *            this is in the form of an first_block_num that is written immediately after the version
    * Version 3: improvement on version 2 to not require the genesis state be provided when not starting
    *            from block 1
    * Version 4: changes the block entry from the serialization of signed_block to a tuple of offset to next entry,
    *            compression_status and pruned_block.
    */
   const uint32_t block_log::max_supported_version = 4;


   template <typename T>
   T read_buffer(const char* buf) {
      T result;
      memcpy(&result, buf, sizeof(T));
      return result;
   }

   struct block_log_preamble {
      uint32_t version         = 0;
      uint32_t first_block_num = 0;
      std::variant<genesis_state, chain_id_type> chain_context;

      chain_id_type chain_id() const {
         return std::visit(overloaded{[](const chain_id_type& id) { return id; },
                                      [](const genesis_state& state) { return state.compute_chain_id(); }},
                           chain_context);
      }

      constexpr static int without_genesis_state_size =
          sizeof(version) + sizeof(first_block_num) + sizeof(chain_id_type) + sizeof(block_log::npos);

      void read(fc::datastream<const char*>& ds) {
        ds.read((char*)&version, sizeof(version));
         EOS_ASSERT(version > 0, block_log_exception, "Block log was not setup properly");
         EOS_ASSERT(
             block_log::is_supported_version(version), block_log_unsupported_version,
             "Unsupported version of block log. Block log version is ${version} while code supports version(s) "
             "[${min},${max}]",
             ("version", version)("min", block_log::min_supported_version)("max", block_log::max_supported_version));

         first_block_num = 1;
         if (version != 1) {
            ds.read((char*)&first_block_num, sizeof(first_block_num));
         }

         if (block_log::contains_genesis_state(version, first_block_num)) {
            chain_context.emplace<genesis_state>();
            fc::raw::unpack(ds, std::get<genesis_state>(chain_context));
         } else if (block_log::contains_chain_id(version, first_block_num)) {
            chain_context = chain_id_type{}; 
            ds >> std::get<chain_id_type>(chain_context);
         } else {
            EOS_THROW(block_log_exception,
                      "Block log is not supported. version: ${ver} and first_block_num: ${fbn} does not contain "
                      "a genesis_state nor a chain_id.",
                      ("ver", version)("fbn", first_block_num));
         }

         if (version != 1) {
            auto                                    expected_totem = block_log::npos;
            std::decay_t<decltype(block_log::npos)> actual_totem;
            ds.read((char*)&actual_totem, sizeof(actual_totem));

            EOS_ASSERT(
                actual_totem == expected_totem, block_log_exception,
                "Expected separator between block log header and blocks was not found( expected: ${e}, actual: ${a} )",
                ("e", fc::to_hex((char*)&expected_totem, sizeof(expected_totem)))(
                    "a", fc::to_hex((char*)&actual_totem, sizeof(actual_totem))));
         }
      }

      template <typename Stream>
      void write(Stream& ds) const {
         EOS_ASSERT(version >= 2, block_log_exception, "this method does not support writeing block log ${version}",
                    ("version", version));
         ds.write(reinterpret_cast<const char*>(&version), sizeof(version));
         ds.write(reinterpret_cast<const char*>(&first_block_num), sizeof(first_block_num));

         std::visit(overloaded{[&ds](const chain_id_type& id) { ds << id; },
                               [&ds](const genesis_state& state) {
                                  auto data = fc::raw::pack(state);
                                  ds.write(data.data(), data.size());
                               }},
                    chain_context);

         auto totem = block_log::npos;
         ds.write(reinterpret_cast<const char*>(&totem), sizeof(totem));
      }
   };

   namespace {
      /// calculate the offset from the start of serialized block entry to block start
      int offset_to_block_start(uint32_t version) { 
         if (version < 4) return 0;
         return sizeof(uint32_t) + 1;
      }

      class log_entry_v4 : public pruned_block {
      public:
         pruned_transaction::cf_compression_type compression;
         uint32_t                                offset;
      };


      template <typename Stream>
      void unpack(Stream& ds, log_entry_v4& entry){
         auto start_pos = ds.tellp();
         fc::raw::unpack(ds, entry.offset);
         uint8_t compression;
         fc::raw::unpack(ds, compression);
         entry.compression = static_cast<pruned_transaction::cf_compression_type>(compression);
         EOS_ASSERT(entry.compression == pruned_transaction::cf_compression_type::none, block_log_exception,
                  "Only support compression_type none");
         fc::raw::unpack(ds, static_cast<pruned_block&>(entry));
         EOS_ASSERT(ds.tellp() - start_pos + sizeof(uint64_t) == entry.offset , block_log_exception,
                  "Invalid block log entry offset");
      }

      std::vector<char> pack(const pruned_block& block, pruned_transaction::cf_compression_type compression) {
         // In version 4 of the irreversible blocks log format, these log entries consists of the following in order:
         //    1. An uint32_t offset from the start of this log entry to the start of the next log entry.
         //    2. An uint8_t indicating the compression status for the serialization of the pruned_block following this.
         //    3. The serialization of a pruned_block representation of the block for the entry including padding.

         std::size_t padded_size = block.maximum_pruned_pack_size(compression);
         std::vector<char> buffer(padded_size + offset_to_block_start(4));
         fc::datastream<char*> stream(buffer.data(), buffer.size());

         uint32_t offset      = buffer.size() + sizeof(uint64_t);
         stream.write((char*)&offset, sizeof(offset));
         fc::raw::pack(stream, static_cast<uint8_t>(compression));
         block.pack(stream, compression);
         return buffer;
      }

      std::vector<char> pack(const log_entry_v4& entry) {
         return pack(static_cast<const pruned_block&>(entry), entry.compression);
      }

      using log_entry = std::variant<log_entry_v4, signed_block>;

      template <typename Stream>
      void unpack(Stream& ds, log_entry& entry) {
         std::visit(
             overloaded{[&ds](signed_block& v) { fc::raw::unpack(ds, v); }, [&ds](log_entry_v4& v) { unpack(ds, v); }},
             entry);
      }
   } // namespace

  namespace detail {
      class block_log_impl {
         public:
            pruned_block_ptr   head;
            fc::cfile          block_file;
            fc::cfile          index_file;
            bool               open_files                   = false;
            bool               genesis_written_to_block_log = false;
            block_log_preamble preamble;

            inline void check_open_files() {
               if( !open_files ) {
                  reopen();
               }
            }

            void reopen() {
               close();

               // open to create files if they don't exist
               //ilog("Opening block log at ${path}", ("path", my->block_file.generic_string()));
               block_file.open( LOG_WRITE_C );
               index_file.open( LOG_WRITE_C );

               close();

               block_file.open( LOG_RW_C );
               index_file.open( LOG_RW_C );

               open_files = true;
            }

            void close() {
               if( block_file.is_open() )
                  block_file.close();
               if( index_file.is_open() )
                  index_file.close();
               open_files = false;
            }

            void reset( const pruned_block_ptr& first_block, pruned_transaction::cf_compression_type segment_compression, uint32_t first_block_num );

            void flush();

            uint64_t append(const pruned_block_ptr& b, pruned_transaction::cf_compression_type segment_compression);

            uint64_t write_log_entry(const pruned_block&                     b,
                                     pruned_transaction::cf_compression_type segment_compression);

            void                          read_block_header(block_header& bh, uint64_t file_pos);
            std::unique_ptr<pruned_block> read_block(uint64_t pos);
            void                          read_head();            
      };
   } // namespace detail

   namespace {

   void create_mapped_file(boost::iostreams::mapped_file_sink& sink, const std::string& path, uint64_t size) {
      using namespace boost::iostreams;
      mapped_file_params params(path);
      params.flags         = mapped_file::readwrite;
      params.new_file_size = size;
      params.length        = size;
      params.offset        = 0;
      sink.open(params);
   }

   class index_writer {
    public:
      index_writer(const fc::path& block_index_name, uint32_t blocks_expected)
          : current_position(blocks_expected * sizeof(uint64_t)) {
         create_mapped_file(index, block_index_name.generic_string(), current_position);
      }
      void write(uint64_t pos) {
         current_position -= sizeof(pos);
         memcpy(index.data() + current_position, &pos, sizeof(pos));
      }

      void close() { index.close(); }
    private:
      uint64_t                           current_position = 0;
      boost::iostreams::mapped_file_sink index;
   };
}}} // namespace eosio::chain::detail

FC_REFLECT_DERIVED(eosio::chain::log_entry_v4, (eosio::chain::pruned_block), (compression)(offset) )

namespace eosio { namespace chain {   
namespace {
   /// Provide the readonly view of blocks.log file
   class block_log_data {
      boost::iostreams::mapped_file_source file;
      block_log_preamble                   preamble;
      uint64_t                             first_block_pos = block_log::npos;

    public:
      block_log_data() = default;

      block_log_data(const fc::path& path) { open(path); }

      fc::datastream<const char*> open(const fc::path& path) {
         file.open(path.generic_string());
         fc::datastream<const char*> ds(file.data(), file.size());
         preamble.read(ds);
         first_block_pos = ds.tellp();
         return ds;
      }

      const char*   data() const { return file.data(); }
      uint64_t      size() const { return file.size(); }
      uint32_t      version() const { return preamble.version; }
      uint32_t      first_block_num() const { return preamble.first_block_num; }
      chain_id_type chain_id() const { return preamble.chain_id(); }

      fc::optional<genesis_state> get_genesis_state() const {
         return std::visit(overloaded{[](const chain_id_type&) { return fc::optional<genesis_state>{}; },
                                      [](const genesis_state& state) { return fc::optional<genesis_state>{state}; }},
                           preamble.chain_context);
      }

      uint32_t block_num_at(uint64_t position) const {
         // to derive blknum_offset==14 see block_header.hpp and note on disk struct is packed
         //   block_timestamp_type timestamp;                  //bytes 0:3
         //   account_name         producer;                   //bytes 4:11
         //   uint16_t             confirmed;                  //bytes 12:13
         //   block_id_type        previous;                   //bytes 14:45, low 4 bytes is big endian block number of
         //   previous block

         int blknum_offset = 14;
         blknum_offset += offset_to_block_start(version());
         uint32_t prev_block_num = read_buffer<uint32_t>(data() + position + blknum_offset);
         return fc::endian_reverse_u32(prev_block_num) + 1;
      }

      uint32_t last_block_num() const { return block_num_at(last_block_position()); }

      uint32_t num_blocks() const {
         if (first_block_pos == file.size())
            return 0;
         return last_block_num() - first_block_num() + 1;
      }

      uint64_t first_block_position() const { return first_block_pos; }
      uint64_t last_block_position() const { return read_buffer<uint64_t>(data() + size() - sizeof(uint64_t)); }

      block_id_type validate_block(fc::datastream<const char*>& ds, block_id_type previous_block_id);
   };

   /// Provide the readonly view of blocks.index file
   class block_log_index {
      boost::iostreams::mapped_file_source file;

    public:
      block_log_index() = default;
      block_log_index(const fc::path& path) { open(path); }

      void open(const fc::path& path) { file.open(path.generic_string()); }

      using iterator         = const uint64_t*;
      using reverse_iterator = std::reverse_iterator<iterator>;

      iterator begin() const { return reinterpret_cast<iterator>(file.data()); }
      iterator end() const { return reinterpret_cast<iterator>(file.data() + file.size()); }

      reverse_iterator rbegin() const { return std::make_reverse_iterator(end()); }
      reverse_iterator rend() const { return std::make_reverse_iterator(begin()); }

      int num_blocks() const { return file.size() / sizeof(uint64_t); }

      uint64_t position_at_offset(uint32_t offset) const { return *(begin() + offset); }
   };

   /// Provide the readonly view for both blocks.log and blocks.index files
   struct block_log_archive {
      fc::path        block_file_name, index_file_name; // full pathname for blocks.log and blocks.index
      block_log_data  log_data;
      block_log_index log_index;

      block_log_archive(fc::path block_dir) {
         block_file_name = block_dir / "blocks.log";
         index_file_name = block_dir / "blocks.index";

         log_data.open(block_file_name);
         log_index.open(index_file_name);

         uint32_t log_num_blocks   = log_data.num_blocks();
         uint32_t index_num_blocks = log_index.num_blocks();

         EOS_ASSERT(
             log_num_blocks == index_num_blocks, block_log_exception,
             "blocks.log says it has ${log_num_blocks} blocks which disagrees ${index_num_blocks} with blocks.index ",
             ("log_num_blocks", log_num_blocks)("index_num_blocks", index_num_blocks));
      }
   };

   /// Used to traverse the block position (i.e. the last 8 bytes in each block log entry) of blocks.log file
   template <typename T>
   struct reverse_block_position_iterator {
      const T& data;
      uint64_t begin_position;
      uint64_t current_position;
      reverse_block_position_iterator(const T& data, uint64_t first_block_pos)
          : data(data)
          , begin_position(first_block_pos - sizeof(uint64_t))
          , current_position(data.size() - sizeof(uint64_t)) {}

      auto addr() const { return data.data() + current_position; }

      uint64_t get_value() {
         if (current_position == begin_position)
            return block_log::npos;
         return read_buffer<uint64_t>(addr());
      }

      void set_value(uint64_t pos) { memcpy(addr(), &pos, sizeof(pos)); }

      reverse_block_position_iterator& operator++() {
         EOS_ASSERT(current_position > begin_position && current_position < data.size(), block_log_exception,
                    "Block log file formatting is incorrect, indicates position location in file: ${pos}, which should "
                    "be between ${begin_pos} and ${last_pos}.",
                    ("pos", current_position)("begin_pos", begin_position)("last_pos", data.size()));

         current_position = read_buffer<uint64_t>(addr()) - sizeof(uint64_t);
         return *this;
      }
   };

   template <typename BlockLogData>
   reverse_block_position_iterator<BlockLogData> get_reverse_block_position_iterator(const BlockLogData& t) {
      return reverse_block_position_iterator<BlockLogData>(t, t.first_block_position());
   }

   template <typename BlockLogData>
   reverse_block_position_iterator<BlockLogData> get_reverse_block_position_iterator(const BlockLogData& t,
                                                                                     uint64_t first_block_position) {
      return reverse_block_position_iterator<BlockLogData>(t, first_block_position);
   }
   } // namespace

   block_log::block_log(const fc::path& data_dir)
       : my(new detail::block_log_impl()) {
      open(data_dir);
   }

   block_log::block_log(block_log&& other) {
      my = std::move(other.my);
   }

   block_log::~block_log() {
      if (my) {
         flush();
         my->close();
         my.reset();
      }
   }

   void block_log::open(const fc::path& data_dir) {
      my->close();

      if (!fc::is_directory(data_dir))
         fc::create_directories(data_dir);

      my->block_file.set_file_path( data_dir / "blocks.log" );
      my->index_file.set_file_path( data_dir / "blocks.index" );
      /* On startup of the block log, there are several states the log file and the index file can be
       * in relation to each other.
       *
       *                          Block Log
       *                     Exists       Is New
       *                 +------------+------------+
       *          Exists |    Check   |   Delete   |
       *   Index         |    Head    |    Index   |
       *    File         +------------+------------+
       *          Is New |   Replay   |     Do     |
       *                 |    Log     |   Nothing  |
       *                 +------------+------------+
       *
       * Checking the heads of the files has several conditions as well.
       *  - If they are the same, do nothing.
       *  - If the index file head is not in the log file, delete the index and replay.
       *  - If the index file head is in the log, but not up to date, replay from index head.
       */
      auto log_size =  fc::exists(my->block_file.get_file_path()) ? fc::file_size( my->block_file.get_file_path() ) : 0;
      auto index_size = fc::exists(my->index_file.get_file_path()) ? fc::file_size( my->index_file.get_file_path() ) : 0;

      if (log_size) {
         ilog("Log is nonempty");
         block_log_data log_data(my->block_file.get_file_path());
         my->preamble.version = log_data.version();
         my->preamble.first_block_num = log_data.first_block_num();

         my->genesis_written_to_block_log = true; // Assume it was constructed properly.

         if (index_size) {
            ilog("Index is nonempty");
            uint64_t block_pos = log_data.last_block_position();

            block_log_index index(my->index_file.get_file_path());
            uint64_t        index_pos = *index.rbegin();
            
            if (block_pos < index_pos) {
               ilog("block_pos < index_pos, close and reopen index_file");
               construct_index();
            } else if (block_pos > index_pos) {
               ilog("Index is incomplete");
               construct_index();
            }
         } else {
            ilog("Index is empty");
            construct_index();
         }
      } else if (index_size) {
         ilog("Index is nonempty, remove and recreate it");
         fc::remove_all( my->index_file.get_file_path() );
      }

      my->reopen();
      if (log_size)
         my->read_head();
   }

   uint64_t detail::block_log_impl::write_log_entry(const pruned_block& b, pruned_transaction::cf_compression_type segment_compression) {
      uint64_t pos = block_file.tellp();
      std::vector<char> buffer;
     
      if (preamble.version >= 4)  {
         buffer = pack(b, segment_compression);
      } else {
#warning: TODO avoid heap allocation
         auto block_ptr = b.to_signed_block();
         EOS_ASSERT(block_ptr, block_log_append_fail, "Unable to convert block to legacy format");
         EOS_ASSERT(segment_compression == pruned_transaction::cf_compression_type::none, block_log_append_fail, 
            "the compression must be \"none\" for legacy format");
         buffer = fc::raw::pack(*block_ptr);
      }
      block_file.write(buffer.data(), buffer.size());
      block_file.write((char*)&pos, sizeof(pos));
      index_file.write((char*)&pos, sizeof(pos));
      return pos;
   }

   uint64_t block_log::append(const signed_block_ptr& b) {
      return this->append(std::make_shared<pruned_block>(*b, true), pruned_transaction::cf_compression_type::none);
   }

   uint64_t block_log::append(const pruned_block_ptr& b, pruned_transaction::cf_compression_type segment_compression) {
      return my->append(b, segment_compression);
   }

   uint64_t detail::block_log_impl::append(const  pruned_block_ptr& b, pruned_transaction::cf_compression_type segment_compression) {
      try {
         EOS_ASSERT( genesis_written_to_block_log, block_log_append_fail, "Cannot append to block log until the genesis is first written" );

         check_open_files();

         block_file.seek_end(0);
         index_file.seek_end(0);
         EOS_ASSERT(index_file.tellp() == sizeof(uint64_t) * (b->block_num() - preamble.first_block_num),
                   block_log_append_fail,
                   "Append to index file occuring at wrong position.",
                   ("position", (uint64_t) index_file.tellp())
                   ("expected", (b->block_num() - preamble.first_block_num) * sizeof(uint64_t)));

         auto pos = write_log_entry(*b, segment_compression);

         head = b;

         flush();

         return pos;
      }
      FC_LOG_AND_RETHROW()
   }

   void block_log::flush() {
      my->flush();
   }

   void detail::block_log_impl::flush() {
      block_file.flush();
      index_file.flush();
   }

   void detail::block_log_impl::reset( const pruned_block_ptr& first_block, pruned_transaction::cf_compression_type segment_compression, uint32_t first_bnum ) {
      close();

      fc::remove_all( block_file.get_file_path() );
      fc::remove_all( index_file.get_file_path() );

      reopen();

      preamble.version = block_log::max_supported_version; // version of 0 is invalid; it indicates that subsequent data was not properly written to the block log
      preamble.first_block_num = first_bnum;
      preamble.write(block_file);

      genesis_written_to_block_log = true;
      
      if (first_block) {
         append(first_block, segment_compression);
      } else {
         head.reset();
      }

      static_assert( block_log::max_supported_version > 0, "a version number of zero is not supported" );
      flush();
   }

   void block_log::reset( const genesis_state& gs, const signed_block_ptr& first_block ) {
      auto b = std::make_shared<pruned_block>(*first_block,true);
      my->preamble.chain_context = gs;
      my->reset(b, pruned_transaction::cf_compression_type::none, 1);
   }

   void block_log::reset( const genesis_state& gs, const pruned_block_ptr& first_block, pruned_transaction::cf_compression_type segment_compression ) {
      my->preamble.chain_context = gs;
      my->reset(first_block,segment_compression, 1);
   }

   void block_log::reset( const chain_id_type& chain_id, uint32_t first_block_num ) {
      EOS_ASSERT( first_block_num > 1, block_log_exception,
                  "Block log version ${ver} needs to be created with a genesis state if starting from block number 1." );
      my->preamble.chain_context = chain_id;
      my->reset(pruned_block_ptr(), pruned_transaction::cf_compression_type::none, first_block_num);
   }

   std::unique_ptr<pruned_block> detail::block_log_impl::read_block(uint64_t pos) {
      block_file.seek(pos);
      auto ds = block_file.create_datastream();
      if (preamble.version >= 4) {
         auto entry = std::make_unique<log_entry_v4>();
         unpack(ds, *entry);
         return entry;
      } else {
         signed_block block;
         fc::raw::unpack(ds, block);
         return std::make_unique<pruned_block>(std::move(block), true);
      }
   }

   void detail::block_log_impl::read_block_header(block_header& bh, uint64_t pos) {
      block_file.seek(pos);
      auto ds = block_file.create_datastream();

      if (preamble.version >= 4 ) {
         uint32_t offset;
         uint8_t  compression;
         fc::raw::unpack(ds, offset);
         fc::raw::unpack(ds, compression);
         EOS_ASSERT( compression == static_cast<uint8_t>(pruned_transaction::cf_compression_type::none), block_log_exception , "Only \"none\" compression type is supported.");
      }
      fc::raw::unpack(ds, bh);
   }

   signed_block_ptr block_log::read_block_by_num(uint32_t block_num) const {
      auto r = read_pruned_block_by_num(block_num);
      return r ? r->to_signed_block() : signed_block_ptr{};
   }

   std::unique_ptr<pruned_block> block_log::read_pruned_block_by_num(uint32_t block_num) const {
      try {
         std::unique_ptr<pruned_block> b;
         uint64_t pos = get_block_pos(block_num);
         if (pos != npos) {
            b = my->read_block(pos);
            EOS_ASSERT(b->block_num() == block_num, block_log_exception,
                      "Wrong block was read from block log.");
         }
         return b;
      } FC_LOG_AND_RETHROW()
   }

   block_id_type block_log::read_block_id_by_num(uint32_t block_num)const {
      try {
         uint64_t pos = get_block_pos(block_num);
         if (pos != npos) {
            block_header bh;
            my->read_block_header(bh, pos);
            EOS_ASSERT(bh.block_num() == block_num, reversible_blocks_exception,
                       "Wrong block header was read from block log.", ("returned", bh.block_num())("expected", block_num));
            return bh.id();
         }
         return {};
      } FC_LOG_AND_RETHROW()
   }

   uint64_t block_log::get_block_pos(uint32_t block_num) const {
      my->check_open_files();
      if (!(my->head && block_num <= my->head->block_num() && block_num >= my->preamble.first_block_num))
         return npos;
      my->index_file.seek(sizeof(uint64_t) * (block_num - my->preamble.first_block_num));
      uint64_t pos;
      my->index_file.read((char*)&pos, sizeof(pos));
      return pos;
   }


   void detail::block_log_impl::read_head() {
      uint64_t pos;

      block_file.seek_end(-sizeof(pos));
      block_file.read((char*)&pos, sizeof(pos));
      if (pos != block_log::npos) {
         head = read_block(pos);
      } 
   }

   signed_block_header* block_log::head() const {
      return my->head.get();
   }

   block_id_type block_log::head_id() const {
      return my->head->id();
   }

   uint32_t block_log::first_block_num() const {
      return my->preamble.first_block_num;
   }

   void block_log::construct_index() {
      ilog("Reconstructing Block Log Index...");
      my->close();

      fc::remove_all( my->index_file.get_file_path() );
      block_log::construct_index(my->block_file.get_file_path(), my->index_file.get_file_path());

      my->reopen();
   } // construct_index

   void block_log::construct_index(const fc::path& block_file_name, const fc::path& index_file_name) {

      ilog("Will read existing blocks.log file ${file}", ("file", block_file_name.generic_string()));
      ilog("Will write new blocks.index file ${file}", ("file", index_file_name.generic_string()));

      block_log_data data(block_file_name);
      const uint32_t num_blocks = data.num_blocks();

      ilog("block log version= ${version}", ("version", data.version()));

      if (num_blocks == 0) {
         return;
      }

      ilog("first block= ${first}         last block= ${last}",
           ("first", data.first_block_num())("last", (data.first_block_num() + num_blocks)));

      index_writer index(index_file_name, num_blocks);
      auto                 iter = get_reverse_block_position_iterator(data);
      uint32_t             blocks_found = 0;

      for (auto iter = get_reverse_block_position_iterator(data); iter.get_value() != npos && blocks_found < num_blocks; ++iter, ++blocks_found) {
         index.write(iter.get_value());
      }

      EOS_ASSERT( blocks_found == num_blocks,
                  block_log_exception,
                  "Block log file at '${blocks_log}' formatting indicated last block: ${last_block_num}, first block: ${first_block_num}, but found ${num} blocks",
                  ("blocks_log", block_file_name.generic_string())("last_block_num", data.last_block_num())("first_block_num", data.first_block_num())("num", blocks_found));

   }

   struct bad_block_excpetion {
      std::exception_ptr inner;
   };

   /// Validate a block log entry and returns the tuple of block number and id if successful. 
   static std::tuple<uint32_t, block_id_type> 
   validate_block_entry(fc::datastream<const char*>& ds, const block_id_type& previous_block_id, log_entry& entry) {
      uint64_t pos = ds.tellp();

      try {
         unpack(ds, entry);
      } catch (...) {
         throw bad_block_excpetion{std::current_exception()};
      }

      const block_header& header    = std::visit([](const auto& v) -> const block_header& { return v; }, entry);
      auto                id        = header.id();
      auto                block_num = block_header::num_from_id(id);
      auto                previous_block_num = block_header::num_from_id(header.previous);

      if (previous_block_num + 1 != block_num) {
         elog("Block ${num} (${id}) skips blocks. Previous block in block log is block ${prev_num} (${previous})",
            ("num", previous_block_num)("id", id)("prev_num", block_header::num_from_id(previous_block_id))(
                  "previous", previous_block_id));
      }

      if (previous_block_id !=  block_id_type() && previous_block_id != header.previous) {
         elog("Block ${num} (${id}) does not link back to previous block. "
            "Expected previous: ${expected}. Actual previous: ${actual}.",
            ("num", block_num)("id", id)("expected", previous_block_id)("actual", header.previous));
      }
      

      uint64_t tmp_pos = std::numeric_limits<uint64_t>::max();
      if (ds.remaining() >= sizeof(tmp_pos)) {
         ds.read(reinterpret_cast<char*>(&tmp_pos), sizeof(tmp_pos));
      }

      EOS_ASSERT(pos == tmp_pos, block_log_exception, "the block position at the end of a block entry is incorrect");
      return std::make_tuple(block_num, id);
   }

   static void write_incomplete_block_data(const fc::path& blocks_dir, fc::time_point now, uint32_t block_num, const char* start, int size) {
      auto tail_path = blocks_dir / std::string("blocks-bad-tail-").append(now).append(".log");
      if (!fc::exists(tail_path)) {
         fc::cfile tail;
         tail.set_file_path(tail_path);
         tail.open(LOG_WRITE_C);
         tail.write(start, size);

         ilog("Data at tail end of block log which should contain the (incomplete) serialization of block ${num} "
              "has been written out to '${tail_path}'.",
              ("num", block_num + 1)("tail_path", tail_path));
      }
   }

   fc::path block_log::repair_log(const fc::path& data_dir, uint32_t truncate_at_block) {
      ilog("Recovering Block Log...");
      EOS_ASSERT(fc::is_directory(data_dir) && fc::is_regular_file(data_dir / "blocks.log"), block_log_not_found,
                 "Block log not found in '${blocks_dir}'", ("blocks_dir", data_dir));

      auto now = fc::time_point::now();

      auto blocks_dir = fc::canonical(data_dir);
      if (blocks_dir.filename().generic_string() == ".") {
         blocks_dir = blocks_dir.parent_path();
      }
      auto backup_dir      = blocks_dir.parent_path();
      auto blocks_dir_name = blocks_dir.filename();
      EOS_ASSERT(blocks_dir_name.generic_string() != ".", block_log_exception, "Invalid path to blocks directory");
      backup_dir = backup_dir / blocks_dir_name.generic_string().append("-").append(now);

      EOS_ASSERT(!fc::exists(backup_dir), block_log_backup_dir_exist,
                 "Cannot move existing blocks directory to already existing directory '${new_blocks_dir}'",
                 ("new_blocks_dir", backup_dir));

      fc::rename(blocks_dir, backup_dir);
      ilog("Moved existing blocks directory to backup location: '${new_blocks_dir}'", ("new_blocks_dir", backup_dir));

      fc::create_directories(blocks_dir);
      auto block_log_path = blocks_dir / "blocks.log";

      ilog("Reconstructing '${new_block_log}' from backed up block log", ("new_block_log", block_log_path));
      auto        block_log_path_string = block_log_path.generic_string();
      const char* block_file_name       = block_log_path_string.c_str();

      uint32_t      block_num = 0;
      block_id_type previous;

      block_log_data log_data;
      auto           ds  = log_data.open(backup_dir / "blocks.log");
      auto           pos = ds.tellp();
      std::string error_msg;

      log_entry entry;
      if (log_data.version() < 4) {
         entry.emplace<signed_block>();
      }

      try {
         try {
            while (ds.remaining() > 0 && block_num < truncate_at_block) {
               std::tie(block_num, previous) = validate_block_entry(ds, previous, entry);
               if (block_num % 1000 == 0)
                  ilog("Verified block ${num}", ("num", block_num));
               pos  = ds.tellp();
            }
         }
         catch (const bad_block_excpetion& e) {
            write_incomplete_block_data(blocks_dir, now, block_num, log_data.data() + pos, log_data.size() - pos);
            std::rethrow_exception(e.inner);
         }
      } catch (const fc::exception& e) {
         error_msg = e.what();
      } catch (const std::exception& e) {
         error_msg = e.what();
      } catch (...) {
         error_msg = "unrecognized exception";
      }

      fc::cfile new_block_file;
      new_block_file.set_file_path(block_log_path);
      new_block_file.open(LOG_WRITE_C);
      new_block_file.write(log_data.data(), pos);

      if (error_msg.size()) {
         ilog("Recovered only up to block number ${num}. "
              "The block ${next_num} could not be deserialized from the block log due to error:\n${error_msg}",
              ("num", block_num)("next_num", block_num + 1)("error_msg", error_msg));
      } else if (block_num == truncate_at_block && pos < log_data.size()) {
         ilog("Stopped recovery of block log early at specified block number: ${stop}.", ("stop", truncate_at_block));
      } else {
         ilog("Existing block log was undamaged. Recovered all irreversible blocks up to block number ${num}.",
              ("num", block_num));
      }
      return backup_dir;
   }

   fc::optional<genesis_state> block_log::extract_genesis_state( const fc::path& data_dir ) {
      return block_log_data(data_dir / "blocks.log").get_genesis_state();
   }
      

   chain_id_type block_log::extract_chain_id( const fc::path& data_dir ) {
      return block_log_data(data_dir / "blocks.log").chain_id();
   }

   bool prune(pruned_transaction& ptx) { 
      ptx.prune_all();
      return true;
   }
   
   void block_log::prune_transactions(uint32_t block_num, const std::vector<transaction_id_type>& ids) {
      try {
         EOS_ASSERT(my->preamble.version >= 4, block_log_exception, "The block log version ${version} does not support transaction pruning.", ("version", my->preamble.version));
         uint64_t pos = get_block_pos(block_num);
         EOS_ASSERT(pos != npos, block_log_exception,
                     "Specified block_num ${block_num} does not exist in block log.", ("block_num", block_num));

         log_entry_v4 entry;   
         my->block_file.seek(pos);
         auto ds = my->block_file.create_datastream();
         unpack(ds, entry);

         EOS_ASSERT(entry.block_num() == block_num, block_log_exception,
                     "Wrong block was read from block log.");

         auto pruner = overloaded{[](transaction_id_type&) { return false; },
                                  [&ids](pruned_transaction& ptx) { return  std::find(ids.begin(), ids.end(), ptx.id()) != ids.end() && prune(ptx); }};

         bool pruned = false;
         for (auto& trx : entry.transactions) {
            pruned |= trx.trx.visit(pruner);
         }

         if (pruned) {
            my->block_file.seek(pos);
            std::vector<char> buffer = pack(entry);
            EOS_ASSERT(buffer.size() <= entry.offset, block_log_exception, "Not enough space reserved in block log entry to serialize pruned block.");
            my->block_file.write(buffer.data(), buffer.size());
            my->block_file.flush();
         }
      }
      FC_LOG_AND_RETHROW()
   }

   bool block_log::contains_genesis_state(uint32_t version, uint32_t first_block_num) {
      return version <= 2 || first_block_num == 1;
   }

   bool block_log::contains_chain_id(uint32_t version, uint32_t first_block_num) {
      return version >= 3 && first_block_num > 1;
   }

   bool block_log::is_supported_version(uint32_t version) {
      return std::clamp(version, min_supported_version, max_supported_version) == version;
   }

   bool block_log::trim_blocklog_front(const fc::path& block_dir, const fc::path& temp_dir, uint32_t truncate_at_block) {
      EOS_ASSERT( block_dir != temp_dir, block_log_exception, "block_dir and temp_dir need to be different directories" );
      
      ilog("In directory ${dir} will trim all blocks before block ${n} from blocks.log and blocks.index.",
           ("dir", block_dir.generic_string())("n", truncate_at_block));

      block_log_archive archive(block_dir);

      uint32_t truncate_block_offset = truncate_at_block - archive.log_data.first_block_num();

      if (truncate_at_block <= archive.log_data.first_block_num()) {
         ilog("There are no blocks before block ${n} so do nothing.", ("n", truncate_at_block));
         return false;
      }
      if (truncate_at_block > archive.log_data.last_block_num()) {
         ilog("All blocks are before block ${n} so do nothing (trim front would delete entire blocks.log).", ("n", truncate_at_block));
         return false;
      }

      // ****** create the new block log file and write out the header for the file
      fc::create_directories(temp_dir);
      fc::path new_block_filename = temp_dir / "blocks.log";
      if (fc::remove(new_block_filename)) {
         ilog("Removing old blocks.out file");
      }
   
      static_assert( block_log::max_supported_version == 4,
                     "Code was written to support format of version 4, need to update this code for latest format." );
      
      // offset bytes to shift from old blocklog position to new blocklog position
      const auto num_blocks_to_truncate = truncate_at_block - archive.log_data.first_block_num();
      const uint64_t original_file_block_pos = archive.log_index.position_at_offset(num_blocks_to_truncate);
      const uint64_t pos_delta = original_file_block_pos - block_log_preamble::without_genesis_state_size;

      // all blocks to copy to the new blocklog
      const uint64_t to_write = archive.log_data.size() - original_file_block_pos;
      const auto new_block_file_size = to_write + block_log_preamble::without_genesis_state_size;

      boost::iostreams::mapped_file_sink new_block_file;
      create_mapped_file(new_block_file, new_block_filename.generic_string(), new_block_file_size);
      fc::datastream<char*> ds(new_block_file.data(), new_block_file.size());

      block_log_preamble preamble;
      preamble.version         = block_log::max_supported_version;
      preamble.first_block_num = truncate_at_block;
      preamble.chain_context              = archive.log_data.chain_id();
      preamble.write(ds);

      memcpy(new_block_file.data() + block_log_preamble::without_genesis_state_size, archive.log_data.data() + original_file_block_pos, to_write);

      fc::path new_index_filename = temp_dir / "blocks.index";
      index_writer index(new_index_filename, archive.log_index.num_blocks() - num_blocks_to_truncate);

      reverse_block_position_iterator<boost::iostreams::mapped_file_sink> itr(new_block_file, block_log_preamble::without_genesis_state_size);

      for (; itr.get_value() != block_log::npos; ++itr) {
         auto new_pos = itr.get_value() - pos_delta;
         index.write(new_pos);
         itr.set_value(new_pos);
      }

      index.close();
      new_block_file.close();

      fc::path old_log = temp_dir / "old.log";
      rename(archive.block_file_name, old_log);
      rename(new_block_filename, archive.block_file_name);
      fc::path old_ind = temp_dir / "old.index";
      rename(archive.index_file_name, old_ind);
      rename(new_index_filename, archive.index_file_name);

      return true;
   }

   int block_log::trim_blocklog_end(fc::path block_dir, uint32_t n) {       //n is last block to keep (remove later blocks)
      
      block_log_archive archive(block_dir);

      ilog("In directory ${block_dir} will trim all blocks after block ${n} from ${block_file} and ${index_file}",
         ("block_dir", block_dir.generic_string())("n", n)("block_file",archive.block_file_name.generic_string())("index_file", archive.index_file_name.generic_string()));

      if (n < archive.log_data.first_block_num()) {
         dlog("All blocks are after block ${n} so do nothing (trim_end would delete entire blocks.log)",("n", n));
         return 1;
      }
      if (n > archive.log_data.last_block_num()) {
         dlog("There are no blocks after block ${n} so do nothing",("n", n));
         return 2;
      }

      auto to_trim_block_offset   = n + 1 - archive.log_data.first_block_num();
      auto to_trim_block_position = archive.log_index.position_at_offset(to_trim_block_offset);
      auto index_end              = to_trim_block_offset * sizeof(uint64_t);

      boost::filesystem::resize_file(archive.block_file_name, to_trim_block_position);
      boost::filesystem::resize_file(archive.index_file_name, index_end);
      ilog("blocks.index has been trimmed to ${index_end} bytes", ("index_end", index_end));
      return 0;
   }

   void block_log::smoke_test(fc::path block_dir) {

      block_log_archive archive(block_dir);

      ilog("blocks.log and blocks.index agree on number of blocks");

      uint32_t delta = std::max(archive.log_index.num_blocks() >> 3, 1);
      uint32_t expected_block_num = archive.log_data.first_block_num();

      for (auto pos_itr = archive.log_index.begin(); pos_itr < archive.log_index.end(); pos_itr += delta, expected_block_num += delta) {
         uint64_t block_position = *pos_itr;
         uint32_t actual_block_num = archive.log_data.block_num_at(block_position);
         EOS_ASSERT(actual_block_num == expected_block_num, block_log_exception,
                    "At position ${pos} in ${file} expected to find ${exp_bnum} but found ${act_bnum}",
                    ("pos", block_position)("file", archive.block_file_name.generic_string())("exp_bnum", actual_block_num)("act_bnum", actual_block_num));
      }
   }
}} /// eosio::chain
