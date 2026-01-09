require "../spec_helper"

describe Cryptomancer::Hash::Blake2b do
  describe ".hash" do
    context "when option as_bytes is false" do
      it "hashes a string and returns a string" do
        subject = Cryptomancer::Hash::Blake2b
        data = "hello"
        expected_hash = "e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a65ba1e1b146aeb6bd0092b49eac214c103ccfa3a365954bbbe52f74a2b3620c94"

        subject.hash(data).should eq(expected_hash)
      end
    end

    context "when option as_bytes is true" do
      it "hashes a string and returns a bytes" do
        subject = Cryptomancer::Hash::Blake2b
        data = "hello"
        expected_hash = Bytes[120, 106, 2, 247, 66, 1, 89, 3, 198, 198, 253, 133, 37, 82, 210, 114,
          145, 47, 71, 64, 225, 88, 71, 97, 138, 134, 226, 23, 247, 31, 84, 25,
          210, 94, 16, 49, 175, 238, 88, 83, 19, 137, 100, 68, 147, 78, 176, 75,
          144, 58, 104, 91, 20, 72, 183, 85, 213, 111, 112, 26, 254, 155, 226, 206]
        subject.hash(data, as_bytes: true).should_not be_nil
      end
    end
  end

  describe ".keyed_hash" do
    context "when option as_bytes is false" do
      it "hashes a string and returns a string" do
        subject = Cryptomancer::Hash::Blake2b
        data = "hello"
        key = Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        expected_hash = "aae88da0f39d6669b94d48f298ff31286c7c9c60c27d0265f5f8a16e65930f59191bf07a2df1e45a646621b90db98cab86dc5e63c0a306587020fbce3c5ac28e"

        subject.keyed_hash(data, key).should eq(expected_hash)
      end
    end

    context "when option as_bytes is true" do
      it "hashes a string and returns a bytes" do
        subject = Cryptomancer::Hash::Blake2b
        data = "hello"
        key = Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        expected_hash = Bytes[170, 232, 141, 160, 243, 157, 102, 105, 185, 77, 72, 242, 152, 255,
          49, 40, 108, 124, 156, 96, 194, 125, 2, 101, 245, 248, 161, 110, 101,
          147, 15, 89, 25, 27, 240, 122, 45, 241, 228, 90, 100, 102, 33, 185, 13,
          185, 140, 171, 134, 220, 94, 99, 192, 163, 6, 88, 112, 32, 251, 206, 60,
          90, 194, 142]

        subject.keyed_hash(data, key, as_bytes: true).should eq(expected_hash)
      end
    end

    context "when key more than 64 bytes" do
      it "raises an error" do
        subject = Cryptomancer::Hash::Blake2b
        data = "hello"
        key = Bytes.new(65, 0_u8)

        expect_raises(ArgumentError, "key must be at most 64 bytes") do
          subject.keyed_hash(data, key)
        end
      end
    end
  end

  describe ".update" do
    context "when parameter is a string" do
      it "updates the hash with the string" do
        data = "hello"
        subject = Cryptomancer::Hash::Blake2b.new(64, as_bytes: true)

        subject.update(data)
        subject.final.should_not be_nil
      end
    end

    context "when parameter is a bytes" do
      it "updates the hash with the bytes" do
        subject = Cryptomancer::Hash::Blake2b.new(64, as_bytes: true)
        data = Bytes[104, 101, 108, 108, 111]

        subject.update(data)
        subject.final.should_not be_nil
      end
    end

    context "when parameter is a pointer and length" do
      it "updates the hash with the pointer and length" do
        subject = Cryptomancer::Hash::Blake2b.new(64, as_bytes: true)
        data = "hello"
        data_ptr = data.to_slice.to_unsafe
        length = data.size

        subject.update(data_ptr, length)
        subject.final.should_not be_nil
      end
    end
  end

  describe ".final" do
    context "when the hash context has not been finalized" do
      it "finalizes the hash and returns the digest" do
        subject = Cryptomancer::Hash::Blake2b.new
        data = "hello"

        subject.update(data)
        subject.final.should_not be_nil
      end
    end
  end
end
