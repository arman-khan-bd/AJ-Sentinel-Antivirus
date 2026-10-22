use crate::detection::heuristics::pe::calculate_entropy;

#[test]
fn test_entropy_calculation() {
    // Zero / empty data
    assert_eq!(calculate_entropy(&[]), 0.0);

    // Uniform bytes (all 0xAA) -> entropy should be 0.0
    let uniform = vec![0xAAu8; 1024];
    assert_eq!(calculate_entropy(&uniform), 0.0);

    // Completely distributed bytes 0..255 -> maximum entropy ~ 8.0
    let mut distributed = Vec::new();
    for _ in 0..10 {
        for b in 0..=255u8 {
            distributed.push(b);
        }
    }
    let ent = calculate_entropy(&distributed);
    assert!((ent - 8.0).abs() < 0.001, "Expected ~8.0 entropy, got {}", ent);
}
