# BLAKE2b cryptographic hash function implementation
# Based on RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)
# https://datatracker.ietf.org/doc/html/rfc7693

module Cryptomancer
  module Hash
    class Blake2b
      # Block size in bytes
      BLOCK_SIZE = 128

      # Word size in bytes
      WORD_SIZE = 8

      # Number of rounds
      ROUNDS = 12

      # Initialization vector (IV) - first 64 bits of the fractional parts of the square roots of the first 8 primes
      IV = [
        0x6a09e667f3bcc908_u64,
        0xbb67ae8584caa73b_u64,
        0x3c6ef372fe94f82b_u64,
        0xa54ff53a5f1d36f1_u64,
        0x510e527fade682d1_u64,
        0x9b05688c2b3e6c1f_u64,
        0x1f83d9abfb41bd6b_u64,
        0x5be0cd19137e2179_u64,
      ]

      # Message schedule permutation table
      SIGMA = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
      ]

      @h : Array(UInt64)
      @t : Array(UInt64)
      @buffer : Bytes
      @buffer_offset : Int32
      @digest_length : UInt8
      @finalized : Bool

      # Initialize BLAKE2b hash context
      #
      # * `digest_length` - Output length in bytes (1-64, default: 64)
      # * `key` - Optional key for keyed hashing (MAC mode), max 64 bytes
      # * `salt` - Optional salt, exactly 16 bytes
      # * `personalization` - Optional personalization string, exactly 16 bytes
      def initialize(
        digest_length : UInt8 = 64,
        key : Bytes? = nil,
        salt : Bytes? = nil,
        personalization : Bytes? = nil,
        as_bytes : Bool = false,
      )
        validate_parameters(digest_length, key, salt, personalization)

        @digest_length = digest_length
        @h = IV.dup
        @t = [0_u64, 0_u64]
        @buffer = Bytes.new(BLOCK_SIZE)
        @buffer_offset = 0
        @finalized = false
        @as_bytes = as_bytes

        initialize_parameter_block(key, salt, personalization)
        process_key(key) if key
      end

      # Update hash with new data
      def update(data : Bytes) : Nil
        update(data.to_unsafe, data.size)
      end

      # Update hash with new data
      def update(data : String) : Nil
        update(data.to_slice)
      end

      # Update hash with new data
      def update(data : Pointer(UInt8), length : Int32) : Nil
        if @finalized
          raise RuntimeError.new("Hash context has been finalized")
        end

        data_ptr = data
        remaining = length

        # Process any buffered data first
        if @buffer_offset > 0
          space = BLOCK_SIZE - @buffer_offset
          to_copy = remaining < space ? remaining : space
          @buffer[@buffer_offset, to_copy].copy_from(data_ptr.to_slice(to_copy))
          @buffer_offset += to_copy
          remaining -= to_copy
          data_ptr += to_copy

          if @buffer_offset == BLOCK_SIZE
            @t[0] += BLOCK_SIZE.to_u64
            compress(@buffer, false)
            @buffer = Slice(UInt8).new(BLOCK_SIZE)
            @buffer_offset = 0
          end
        end

        # Process full blocks
        while remaining >= BLOCK_SIZE
          block = data_ptr.to_slice(BLOCK_SIZE)
          @t[0] += BLOCK_SIZE.to_u64
          compress(block, false)
          data_ptr += BLOCK_SIZE
          remaining -= BLOCK_SIZE
        end

        # Buffer remaining data
        if remaining > 0
          @buffer[0, remaining].copy_from(data_ptr.to_slice(remaining))
          @buffer_offset = remaining
        end
      end

      # Finalize hash and return digest
      def final : Bytes | String
        if @finalized
          raise RuntimeError.new("Hash context has been finalized")
        end

        @finalized = true

        # Add padding
        @t[0] += @buffer_offset.to_u64
        @t[1] = (@t[0] < @buffer_offset.to_u64) ? 1_u64 : 0_u64

        # Zero out remaining buffer
        (@buffer_offset...BLOCK_SIZE).each do |i|
          @buffer[i] = 0_u8
        end

        # Final compression
        compress(@buffer, true)

        # Extract digest
        digest = Bytes.new(@digest_length)
        h_ptr = @h.to_unsafe.as(UInt8*)
        available_bytes = WORD_SIZE * @h.size
        copy_size = Math.min(@digest_length.to_i32, available_bytes)

        if copy_size > 0
          digest.copy_from(h_ptr.to_slice(copy_size))
        end

        @as_bytes ? digest[0, @digest_length] : digest.hexstring
      end

      # Compute hash of data
      def self.hash(data : String | Bytes,
                    digest_length : UInt8 = 64,
                    as_bytes : Bool = false) : Bytes | String
        ctx = new(digest_length, as_bytes: as_bytes)
        ctx.update(data.is_a?(String) ? data.to_slice : data)
        ctx.final
      end

      # Compute keyed hash (MAC mode)
      def self.keyed_hash(data : String | Bytes,
                          key : Bytes,
                          digest_length : UInt8 = 64,
                          as_bytes : Bool = false) : Bytes | String
        ctx = new(digest_length: digest_length, key: key, as_bytes: as_bytes)
        ctx.update(data.is_a?(String) ? data.to_slice : data)
        ctx.final
      end

      # Validate initialization parameters
      private def validate_parameters(digest_length, key, salt, personalization) : Nil
        max_digest_length = 8 * WORD_SIZE # Maximum digest length is 8 words (64 bytes)
        if digest_length < 1 || digest_length > max_digest_length
          raise ArgumentError.new("digest_length must be between 1 and #{max_digest_length}")
        end

        max_key_length = 8 * WORD_SIZE # Maximum key length is 8 words (64 bytes)
        if key && key.size > max_key_length
          raise ArgumentError.new("key must be at most #{max_key_length} bytes")
        end

        if salt && salt.size != 16
          raise ArgumentError.new("salt must be exactly 16 bytes")
        end

        if personalization && personalization.size != 16
          raise ArgumentError.new("personalization must be exactly 16 bytes")
        end
      end

      # Initialize parameter block and mix into state
      private def initialize_parameter_block(key, salt, personalization) : Nil
        # Parameter block is 8 words (64 bytes)
        param = Bytes.new(8 * WORD_SIZE, 0_u8)
        param[0] = @digest_length.to_u8
        param[1] = key ? key.size.to_u8 : 0_u8
        param[2] = 1_u8 # fanout
        param[3] = 1_u8 # depth
        # param[4..7] = 0 (leaf length)
        # param[8..11] = 0 (node offset)
        param[12] = 0_u8 # node depth
        param[13] = 0_u8 # inner length
        # param[14..15] = 0 (reserved)

        if salt
          param[16, 16].copy_from(salt)
        end

        if personalization
          param[32, 16].copy_from(personalization)
        end

        # XOR parameter block into state
        param_words = param.to_unsafe.as(UInt64*)
        8.times do |i|
          @h[i] ^= param_words[i]
        end
      end

      # Process key as first block if provided
      private def process_key(key) : Nil
        @buffer[0, key.size].copy_from(key)
        # Zero out the rest of the buffer
        (key.size...BLOCK_SIZE).each do |i|
          @buffer[i] = 0_u8
        end
        @t[0] = BLOCK_SIZE.to_u64
        compress(@buffer, false)
        @buffer = Slice(UInt8).new(BLOCK_SIZE)
        @buffer_offset = 0
      end

      # G mixing function
      private def g(v : Array(UInt64), a : Int32, b : Int32,
                    c : Int32, d : Int32, x : UInt64, y : UInt64) : Nil
        v[a] = v[a] &+ v[b] &+ x
        v[d] = (v[d] ^ v[a]).rotate_right(32)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotate_right(24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = (v[d] ^ v[a]).rotate_right(16)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotate_right(63)
      end

      # Compression function
      private def compress(block : Bytes, last : Bool) : Nil
        # Initialize working state
        v = Array(UInt64).new(16, 0_u64)
        8.times do |i|
          v[i] = @h[i]
        end

        # Mix in IV
        8.times do |i|
          v[i + 8] = IV[i]
        end

        # Mix in counter
        v[12] ^= @t[0]
        v[13] ^= @t[1]

        # Mix in final block flag
        if last
          v[14] ^= 0xffffffffffffffff_u64
        end

        # Convert block to words (little-endian)
        m = Array(UInt64).new(16, 0_u64)
        block_ptr = block.to_unsafe.as(UInt64*)
        16.times do |i|
          m[i] = block_ptr[i]
        end

        # Mixing rounds
        ROUNDS.times do |round|
          # Column step
          g(v, 0, 4, 8, 12, m[SIGMA[round][0]], m[SIGMA[round][1]])
          g(v, 1, 5, 9, 13, m[SIGMA[round][2]], m[SIGMA[round][3]])
          g(v, 2, 6, 10, 14, m[SIGMA[round][4]], m[SIGMA[round][5]])
          g(v, 3, 7, 11, 15, m[SIGMA[round][6]], m[SIGMA[round][7]])

          # Diagonal step
          g(v, 0, 5, 10, 15, m[SIGMA[round][8]], m[SIGMA[round][9]])
          g(v, 1, 6, 11, 12, m[SIGMA[round][10]], m[SIGMA[round][11]])
          g(v, 2, 7, 8, 13, m[SIGMA[round][12]], m[SIGMA[round][13]])
          g(v, 3, 4, 9, 14, m[SIGMA[round][14]], m[SIGMA[round][15]])
        end

        # Update state
        8.times do |i|
          @h[i] ^= v[i] ^ v[i + 8]
        end
      end
    end
  end
end
