pub use zeroize::Zeroize;

pub trait Serializable {
    fn serialize() -> Vec<u8>;
}

pub trait Deserializer {
    fn deserializer(serialized: Vec<u8>);
}
