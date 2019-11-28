pub mod utility;

#[cfg(test)]
mod tests {
    use crate::utility;

    #[test]
    fn recover_pubaddr() {
        let sig = "c28ad430c7c59ef73293778ab38dbd2d7ca50ed730fb2b3c2a9ddca5b23964ef4d651168a8ad00bfad881b8118e0311ceb613983997c68fc35d3615dc3d39a5900";
        let hash = "7a29f3e462f9a2f4d17f9d0271c3d4c26525381469d66c32cea7f6cbc275f9d3";
        let useraddr = "982c3165cd167532a9924d048fec0a7eda9ad2a0";
        let result = utility::recover_user_pubaddress(sig, hash);
        match result {
            Ok(_r) => {
                assert_eq!(useraddr, &_r);
            }
            Err(e) => panic!(e),
        }
    }

    #[test]
    fn keccak256() {
        let result = utility::keccak256("test");
        match result {
            Ok(_r) => {
                assert_eq!(
                    "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658",
                    &_r
                );
            }
            Err(e) => panic!(e),
        }
    }

    #[test]
    fn sha256() {
        let result = utility::sha256("test");
        match result {
            Ok(_r) => {
                assert_eq!(
                    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    &_r
                );
            }
            Err(e) => panic!(e),
        }
    }

    #[test]
    fn hash_text() {
        assert_eq!(
            utility::hash_text("test", "keccak256"),
            utility::keccak256("test")
        );
        assert_eq!(
            utility::hash_text("test", "sha256"),
            utility::sha256("test")
        );
    }
}
