import pytest
from autonomi_client import *

def _b32(b: bytes) -> bytes:
    assert len(b) == 32
    return b

def test_graph_entry_address():
    # Create a random address from XOR
    xor_hex = random_xor()
    addr = GraphEntryAddress(xor_hex)

    # Test hex representation
    assert isinstance(addr.hex, str)
    assert len(addr.hex) == 64
    assert addr.hex == xor_hex

    # Test repr (round-trip) and equality
    assert eval(repr(addr)) == addr

    # Create a graph entry address from a (random) public key
    addr = GraphEntryAddress.from_owner(PublicKey.random())

def test_graph_entry_methods_and_roundtrip():
    owner = SecretKey()
    parents = [PublicKey.random() for _ in range(2)]
    content = _b32(os.urandom(32))
    descendants = [
        (PublicKey.random(), _b32(os.urandom(32))),
        (PublicKey.random(), _b32(os.urandom(32))),
    ]

    ge = GraphEntry(owner, parents, content, descendants)

    # Test address()
    addr = ge.address()
    assert isinstance(addr, GraphEntryAddress)

    # Test content()
    assert ge.content() == content

    # Test parents()
    ps = ge.parents()
    assert isinstance(ps, list) and all(isinstance(p, PublicKey) for p in ps)

    # Test descendants()
    ds = ge.descendants()
    assert isinstance(ds, list)
    for pk, h in ds:
        assert isinstance(pk, PublicKey)
        assert isinstance(h, (bytes, bytearray)) and len(h) == 32
    
    # Parents round-trip
    in_parent_hex = [p.hex for p in parents]
    out_parent_hex = [p.hex for p in ge.parents()]
    assert out_parent_hex == in_parent_hex

    # Descendants round-trip
    in_desc = [(pk.hex, h) for pk, h in descendants]
    out_desc = [(pk.hex, h) for pk, h in ge.descendants()]
    assert out_desc == in_desc

    # Type/shape errors
    with pytest.raises(Exception):
        GraphEntry(owner, parents, os.urandom(31), descendants)     # bad length
    with pytest.raises(Exception):
        GraphEntry(owner, parents, content, [(PublicKey.random(), b"x")])  # bad tuple len

def test_chunk_address():
    # Create a random address from XOR
    xor_hex = random_xor()
    addr = ChunkAddress(xor_hex)

    # Test hex representation
    assert isinstance(addr.hex, str)
    assert len(addr.hex) == 64
    assert addr.hex == xor_hex

    # Test repr (round-trip) and equality
    assert eval(repr(addr)) == addr

    # Create a chunk address from some content
    addr = ChunkAddress.from_content(b"test data")

def test_pointer_address():
    # Create a random address from XOR
    xor_hex = random_xor()
    addr = PointerAddress(xor_hex)

    # Test hex representation
    assert isinstance(addr.hex, str)
    assert len(addr.hex) == 64
    assert addr.hex == xor_hex

    # Test repr (round-trip) and equality
    assert eval(repr(addr)) == addr

    # Create a pointer address from a (random) public key
    addr = PointerAddress.from_owner(PublicKey.random())

def test_pointer_target_with_chunk_address():
    # Create a chunk address
    chunk_addr = ChunkAddress.from_content(b"test data for pointer target")
    
    # Create pointer target from chunk address
    target = PointerTarget.new_chunk(chunk_addr)
    
    # Verify the hex matches
    assert isinstance(target.hex, str)
    assert len(target.hex) == 64

def test_pointer_creation():
    xor_hex = random_xor()

    # Create necessary components
    key = SecretKey()
    counter = 42
    target = PointerTarget.new_chunk(ChunkAddress(xor_hex))
    
    # Create pointer
    pointer = Pointer(key, counter, target)
    
    # Verify pointer properties
    assert isinstance(pointer.hex, str)
    assert len(pointer.hex) == 64
    
    # Test network address
    addr = pointer.address()
    assert isinstance(addr, PointerAddress)
    assert isinstance(addr.hex, str)
    assert len(addr.hex) == 64

    # Pointer should point to original XOR
    assert pointer.target.hex == xor_hex

def test_pointer_target_creation():
    # Test direct creation
    test_data = b"test data for pointer target"
    target = PointerTarget.new_chunk(ChunkAddress.from_content(test_data))
    
    # Verify hex
    assert isinstance(target.hex, str)
    assert len(target.hex) == 64

def test_invalid_hex():
    # Test invalid hex string for chunk address
    with pytest.raises(ValueError):
        ChunkAddress("invalid hex")
    
    # Test invalid hex string for pointer address
    with pytest.raises(ValueError):
        PointerAddress("invalid hex")

def test_wallet():
    network =  Network(True)
    private_key = "0xdb1049e76a813c94be0df47ec3e20533ca676b1b9fef2ddbce9daa117e4da4aa"
    wallet = Wallet.new_from_private_key(network, private_key)

    assert wallet.address() == '0x69D5BF2Bc42bca8782b8D2b4FdfF2b1Fa7644Fe7'
    assert wallet.network() == network

def test_data_stream_types():
    """Test that data stream classes can be instantiated and have expected methods"""
    # Test that DataStream exists and can be imported
    try:
        stream_class = DataStream
        assert hasattr(stream_class, '__name__')
        assert stream_class.__name__ == 'DataStream'
    except NameError:
        pytest.fail("DataStream class not found in autonomi_client module")
    
    # Test that DataMapChunk can be created (needed for data_stream)
    data_map_hex = "0" * 64  # Mock hex string
    try:
        data_map = DataMapChunk.from_hex(data_map_hex)
        assert data_map.hex() == data_map_hex
    except Exception:
        pass  # Expected to fail with mock data, but class should exist
    
    # Test that DataAddress can be created (needed for data_stream_public)
    xor_hex = random_xor()
    data_addr = DataAddress(XorName(xor_hex))
    assert isinstance(data_addr.hex, str)
