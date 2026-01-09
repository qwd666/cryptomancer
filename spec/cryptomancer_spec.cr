require "./spec_helper"

describe Cryptomancer do
  it "loads the module successfully" do
    Cryptomancer::VERSION.should_not be_nil
  end

  it "provides Blake2b hash function" do
    Cryptomancer::Hash::Blake2b.should_not be_nil
  end

  it "provides Blake2bp hash function" do
    Cryptomancer::Hash::Blake2bp.should_not be_nil
  end
end
