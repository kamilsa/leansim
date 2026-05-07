/// Builds the gossipsub topic string for a subnet's validator signatures.
pub fn subnet_topic(run_id: &str, subnet_id: u32) -> String {
    format!("/leansim/{run_id}/subnet/{subnet_id}")
}

/// Builds the gossipsub topic string for aggregation (local proofs → global).
pub fn aggregation_topic(run_id: &str) -> String {
    format!("/leansim/{run_id}/aggregation")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_topic_format() {
        assert_eq!(subnet_topic("r1", 3), "/leansim/r1/subnet/3");
    }

    #[test]
    fn aggregation_topic_format() {
        assert_eq!(aggregation_topic("r1"), "/leansim/r1/aggregation");
    }
}
