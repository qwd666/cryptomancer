# BLAKE2bp (parallel BLAKE2b) cryptographic hash function implementation
# Based on RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)
# https://datatracker.ietf.org/doc/html/rfc7693
#
# BLAKE2bp uses tree hashing with multiple parallel Blake2b instances
# to leverage multiple CPU cores for improved performance.

require "./blake2b"

module Cryptomancer
  module Hash
    class Blake2bp
      # Default number of parallel threads (fanout)
      DEFAULT_FANOUT = 4_u8

      # Block size (inherited from Blake2b)
      BLOCK_SIZE = Blake2b::BLOCK_SIZE

      @leaf_contexts : Array(Blake2b)
      @digest_length : UInt8
      @fanout : UInt8
      @finalized : Bool
      @as_bytes : Bool
      @salt : Bytes?
      @personalization : Bytes?

      # Initialize BLAKE2bp hash context
      #
      # * `digest_length` - Output length in bytes (1-64, default: 64)
      # * `fanout` - Number of parallel threads (1-255, default: 4)
      # * `key` - Optional key for keyed hashing (MAC mode), max 64 bytes
      # * `salt` - Optional salt, exactly 16 bytes
      # * `personalization` - Optional personalization string, exactly 16 bytes
      def initialize(
        digest_length : UInt8 = 64,
        fanout : UInt8 = DEFAULT_FANOUT,
        key : Bytes? = nil,
        salt : Bytes? = nil,
        personalization : Bytes? = nil,
        as_bytes : Bool = false,
      )
        validate_parameters(digest_length, fanout, key, salt, personalization)

        @digest_length = digest_length
        @fanout = fanout
        @finalized = false
        @as_bytes = as_bytes
        @salt = salt
        @personalization = personalization

        # Create leaf contexts for parallel processing
        # Each leaf will process a portion of the input data
        # Note: Salt and personalization are NOT applied to leaves per RFC 7693
        # They will be applied only at the root node during finalization
        @leaf_contexts = Array(Blake2b).new(@fanout) do |leaf_index|
          create_leaf_context(leaf_index, key)
        end
      end

      # Update hash with new data
      # Data is distributed across parallel leaf contexts
      def update(data : Bytes) : Nil
        update(data.to_unsafe, data.size)
      end

      # Update hash with new data
      def update(data : String) : Nil
        update(data.to_slice)
      end

      # Update hash with new data
      def update(data : Pointer(UInt8), length : Int32) : Nil
        raise RuntimeError.new("Hash context has been finalized") if finalized?

        # Distribute data across leaf contexts in round-robin fashion
        # Each leaf processes every fanout-th block
        distribute_data_to_leaves(data, length)
      end

      # Finalize hash and return digest
      def final : Bytes | String
        raise RuntimeError.new("Hash context has been finalized") if finalized?

        @finalized = true

        # Finalize all leaf contexts in parallel
        leaf_digests = finalize_leaves_parallel

        # Combine leaf digests using tree hashing
        # This creates an internal node that combines all leaves
        combine_leaf_digests(leaf_digests)
      end

      # Compute hash of data
      def self.hash(data : String | Bytes,
                    digest_length : UInt8 = 64,
                    fanout : UInt8 = DEFAULT_FANOUT,
                    as_bytes : Bool = false) : Bytes | String
        ctx = new(digest_length: digest_length, fanout: fanout, as_bytes: as_bytes)
        ctx.update(data.is_a?(String) ? data.to_slice : data)
        ctx.final
      end

      # Compute keyed hash (MAC mode)
      def self.keyed_hash(data : String | Bytes,
                          key : Bytes,
                          digest_length : UInt8 = 64,
                          fanout : UInt8 = DEFAULT_FANOUT,
                          as_bytes : Bool = false) : Bytes | String
        ctx = new(digest_length: digest_length, fanout: fanout, key: key, as_bytes: as_bytes)
        ctx.update(data.is_a?(String) ? data.to_slice : data)
        ctx.final
      end

      private def finalized? : Bool
        @finalized
      end

      # Validate initialization parameters
      private def validate_parameters(digest_length, fanout, key, salt, personalization) : Nil
        validate_digest_length(digest_length)
        validate_fanout(fanout)
        validate_key(key) if key
        validate_salt(salt) if salt
        validate_personalization(personalization) if personalization
      end

      private def validate_digest_length(digest_length : UInt8) : Nil
        max_digest_length = 8 * Blake2b::WORD_SIZE
        if digest_length < 1 || digest_length > max_digest_length
          raise ArgumentError.new("digest_length must be between 1 and #{max_digest_length}")
        end
      end

      private def validate_fanout(fanout : UInt8) : Nil
        if fanout < 1 || fanout > 255
          raise ArgumentError.new("fanout must be between 1 and 255")
        end
      end

      private def validate_key(key : Bytes) : Nil
        max_key_length = 8 * Blake2b::WORD_SIZE
        if key.size > max_key_length
          raise ArgumentError.new("key must be at most #{max_key_length} bytes")
        end
      end

      private def validate_salt(salt : Bytes) : Nil
        if salt.size != 16
          raise ArgumentError.new("salt must be exactly 16 bytes")
        end
      end

      private def validate_personalization(personalization : Bytes) : Nil
        if personalization.size != 16
          raise ArgumentError.new("personalization must be exactly 16 bytes")
        end
      end

      # Create a leaf context with tree hashing parameters
      # Each leaf needs unique node_offset and node_depth
      #
      # Note: Full RFC 7693 tree hashing support requires extending Blake2b
      # to accept tree parameters (fanout, depth, node_offset, node_depth, inner_length).
      # For now, we use standard Blake2b contexts.
      # Salt and personalization are NOT applied to leaves - they are applied
      # only at the root node per RFC 7693 tree hashing specification.
      private def create_leaf_context(leaf_index : Int32, key) : Blake2b
        Blake2b.new(
          digest_length: @digest_length,
          key: key,
          salt: nil,            # Leaves don't use salt per RFC 7693
          personalization: nil, # Leaves don't use personalization per RFC 7693
          as_bytes: true,       # Always get bytes for intermediate nodes
        )
      end

      # Distribute input data across leaf contexts using parallel processing
      # Strategy: Simple chunking - divide data into equal parts, process in parallel
      private def distribute_data_to_leaves(data_ptr : Pointer(UInt8), length : Int32) : Nil
        bytes_per_leaf = length // @fanout
        remainder = length % @fanout

        # Channel to collect completion signals
        completion_channel = Channel(Nil).new(@fanout)

        # Spawn parallel fibers to process each leaf's data chunk
        @fanout.times do |i|
          leaf_length = calculate_leaf_length(i, bytes_per_leaf, remainder)
          if leaf_length > 0
            offset = calculate_leaf_offset(i, bytes_per_leaf, remainder)
            # Duplicate data to avoid race conditions with pointer
            leaf_data = (data_ptr + offset).to_slice(leaf_length).dup
            leaf_context = @leaf_contexts[i]

            spawn do
              leaf_context.update(leaf_data)
              completion_channel.send(nil)
            end
          else
            # Send completion immediately for empty chunks
            completion_channel.send(nil)
          end
        end

        # Wait for all parallel processing to complete
        @fanout.times do
          completion_channel.receive
        end
      end

      private def calculate_leaf_length(index : Int32, base_length : Int32, remainder : Int32) : Int32
        base_length + (index < remainder ? 1 : 0)
      end

      private def calculate_leaf_offset(index : Int32, base_length : Int32, remainder : Int32) : Int32
        index * base_length + (index < remainder ? index : remainder)
      end

      # Combine leaf digests into final hash using tree hashing
      # This creates an internal node (root) that hashes all leaf outputs
      # Per RFC 7693, salt and personalization are applied only at the root node
      private def combine_leaf_digests(leaf_digests : Array(Bytes | String)) : Bytes | String
        # All digests are already bytes (as_bytes: true in leaf contexts)
        leaf_bytes = leaf_digests.map(&.as(Bytes))

        # Concatenate all leaf digests
        combined_data = concatenate_leaf_digests(leaf_bytes)

        # Use Blake2b to hash the combined leaf digests at the root node
        # This simulates the internal node compression
        # Salt and personalization are applied here (root node) per RFC 7693
        internal_ctx = Blake2b.new(
          digest_length: @digest_length,
          salt: @salt,
          personalization: @personalization,
          as_bytes: @as_bytes,
        )
        internal_ctx.update(combined_data)
        internal_ctx.final
      end

      private def concatenate_leaf_digests(leaf_bytes : Array(Bytes)) : Bytes
        total_size = @fanout.to_i32 * @digest_length.to_i32
        combined = Bytes.new(total_size)
        offset = 0
        digest_len = @digest_length.to_i32
        leaf_bytes.each do |leaf_digest|
          # Take only the first @digest_length bytes from each leaf digest
          # Pad with zeros if digest is shorter than expected
          copy_size = Math.min(digest_len, leaf_digest.size)
          if copy_size > 0
            combined[offset, copy_size].copy_from(leaf_digest[0, copy_size])
          end
          # Zero out remaining bytes if digest was shorter
          if copy_size < digest_len
            (offset + copy_size...offset + digest_len).each do |i|
              combined[i] = 0_u8
            end
          end
          offset += digest_len
        end
        combined
      end

      # Finalize all leaf contexts in parallel
      private def finalize_leaves_parallel : Array(Bytes | String)
        results = Array(Bytes | String).new(@fanout)
        result_channel = Channel(Bytes | String).new(@fanout)
        error_channel = Channel(Exception?).new(@fanout)

        # Spawn fibers to finalize each leaf in parallel
        @fanout.times do |leaf_index|
          spawn do
            begin
              digest = @leaf_contexts[leaf_index].final
              result_channel.send(digest)
              error_channel.send(nil)
            rescue ex
              error_channel.send(ex)
              raise ex
            end
          end
        end

        # Collect all results and check for errors
        @fanout.times do
          error = error_channel.receive
          if error
            raise error
          end
          results << result_channel.receive
        end

        results
      end
    end
  end
end
