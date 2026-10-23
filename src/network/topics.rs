/// Builds the gossipsub topic string for a subnet's validator signatures.
pub fn subnet_topic(run_id: &str, subnet_id: u32) -> String {
    format!("/leansim/{run_id}/subnet/{subnet_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_topic_format() {
        assert_eq!(subnet_topic("r1", 3), "/leansim/r1/subnet/3");
    }
}
