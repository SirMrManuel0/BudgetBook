use mo_backend::crypto::{
    hashes::sha256::Sha256,
    traits::hash::{ Hash, KeyDerivate32, Salt, DeriveData, DerivedData },
    errors::hash::HashError
};

//use zeroize::Zeroize;

#[test]
fn hash() {
    let tests: Vec<(Vec<u8>, Vec<u8>)> = vec!(
        (b"Test".to_vec(), hex::decode("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25").unwrap()),
        (b"Here is some text with all s0r7s 0f charac7ers even f0r ++math--**".to_vec(), hex::decode("3bd6ff58091529f43e69229ba9f7d6bfb85525d38be1fd3b0af10b99a4790d11").unwrap()),
    );
    for (text, expected) in tests {
        let result_hashed: Result<Vec<u8>, HashError> = Sha256::default_hash(text.as_slice());
        let result = match  result_hashed {
            Ok(v) => v,
            Err(_) => { assert_eq!(1, 2); return (); }
        };
        assert_eq!(result, expected);
    }
}

#[test]
fn derive32() {
    let tests: Vec<(Vec<u8>, DeriveData)> = vec!(
        (hex::decode("550dfa816453cfb539b454f271c7cf419ab7938b63613261da8f6fe90ee7831d").unwrap(), DeriveData{ secret: b"This is a secret".to_vec(), hashes: 10, salt: None}),
        (hex::decode("2e1573e82b30d2801c9462aac51d0a089dd644ca68d4f5676fc691a40f4ce493").unwrap(), DeriveData{ secret: b"This is a secret*-/*89+6854+7*7325!".to_vec(), hashes: 10, salt: Some(Salt{ length: 8, data: Some(b"Hello".to_vec()) }) }),
    );
    for (expected, data) in tests {
        let result_derived: Result<DerivedData, HashError> = Sha256::derive32(&data);
        let derived: DerivedData = match result_derived {
            Ok(d) => d,
            Err(_) => { assert_eq!(1, 2); return (); }
        };
        assert_eq!(derived.key, expected);
    }
    for i in 10..=20 as usize {
        let text: Vec<u8> = b"This is some secret being extend by some random salt".to_vec();
        let data: DeriveData = DeriveData{ secret: text, hashes: 10, salt: Some(Salt{ length: i, data: None }) };
        let result_derived: Result<DerivedData, HashError> = Sha256::derive32(&data);
        match result_derived {
            Ok(d) => d,
            Err(_) => { assert_eq!(1, 2); return (); }
        };
        assert_eq!(0, 0);
    }
}