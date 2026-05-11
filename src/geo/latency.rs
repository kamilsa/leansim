use rand::Rng;
use std::collections::HashMap;

/// Embedded country-to-country RTT data (milliseconds, 89 countries).
const LATENCY_JSON: &str = include_str!("../../data/country_latencies.json");

/// Embedded country weights for node distribution (17 countries).
const WEIGHTS_JSON: &str = include_str!("../../data/weights.json");

/// Per-edge latency with optional jitter.
#[derive(Debug, Clone, Copy)]
pub struct LatencyParams {
    pub base_ms: f64,
    pub jitter_ratio: f64,
}

impl LatencyParams {
    /// Sample latency in ms with uniform jitter: base_ms ± base_ms × jitter_ratio.
    pub fn sample_ms(&self, rng: &mut impl Rng) -> f64 {
        let spread = self.base_ms * self.jitter_ratio;
        let jitter = rng.gen_range(-spread..spread);
        (self.base_ms + jitter).max(0.5)
    }
}

/// Loaded once: latency matrix (country → country → ms) and per-country defaults.
pub struct CountryLatencyModel {
    /// country → (target_country → base_ms)
    matrix: HashMap<String, HashMap<String, f64>>,
    /// country → default_ms (used when target country not in matrix row)
    defaults: HashMap<String, f64>,
    /// Global fallback when nothing matches.
    global_default_ms: f64,
    /// Jitter computation: categories based on base latency.
    jitter_thresholds: Vec<(f64, f64)>, // (max_ms, jitter_ratio)
}

impl CountryLatencyModel {
    pub fn load() -> Self {
        let raw: HashMap<String, serde_json::Value> =
            serde_json::from_str(LATENCY_JSON).expect("Failed to parse country_latencies.json");

        let mut matrix: HashMap<String, HashMap<String, f64>> = HashMap::new();
        let mut defaults: HashMap<String, f64> = HashMap::new();

        for (country, data) in &raw {
            let mut row: HashMap<String, f64> = HashMap::new();
            if let Some(obj) = data.as_object() {
                for (target, val) in obj {
                    if target == "default" {
                        defaults.insert(country.clone(), val.as_f64().unwrap_or(100.0));
                    } else if let Some(ms) = val.as_f64() {
                        row.insert(target.clone(), ms);
                    }
                }
            }
            matrix.insert(country.clone(), row);
        }

        Self {
            matrix,
            defaults,
            global_default_ms: 100.0,
            jitter_thresholds: vec![
                (30.0, 0.05),
                (80.0, 0.10),
                (f64::INFINITY, 0.15),
            ],
        }
    }

    /// Look up latency between two countries. Fallback chain:
    /// direct lookup → source default → reverse lookup → target default → global fallback
    pub fn get_latency(&self, from: &str, to: &str) -> LatencyParams {
        let base_ms = self.lookup_ms(from, to);
        let jitter_ratio = self
            .jitter_thresholds
            .iter()
            .find(|(max_ms, _)| base_ms < *max_ms)
            .map(|(_, ratio)| *ratio)
            .unwrap_or(0.15);
        LatencyParams {
            base_ms,
            jitter_ratio,
        }
    }

    fn lookup_ms(&self, from: &str, to: &str) -> f64 {
        // 1. Direct lookup
        if let Some(row) = self.matrix.get(from) {
            if let Some(&ms) = row.get(to) {
                return ms;
            }
        }
        // 2. Source default
        if let Some(&ms) = self.defaults.get(from) {
            return ms;
        }
        // 3. Reverse lookup
        if let Some(row) = self.matrix.get(to) {
            if let Some(&ms) = row.get(from) {
                return ms;
            }
        }
        // 4. Target default
        if let Some(&ms) = self.defaults.get(to) {
            return ms;
        }
        // 5. Global fallback
        self.global_default_ms
    }
}

/// Country weights for node distribution.
pub struct CountryWeights {
    countries: Vec<String>,
    weights: Vec<f64>,
    total_weight: f64,
}

impl CountryWeights {
    pub fn load() -> Self {
        let raw: HashMap<String, f64> =
            serde_json::from_str(WEIGHTS_JSON).expect("Failed to parse weights.json");
        let mut countries = Vec::new();
        let mut weights = Vec::new();
        let mut total = 0.0;
        for (country, weight) in &raw {
            countries.push(country.clone());
            weights.push(*weight);
            total += weight;
        }
        Self {
            countries,
            weights,
            total_weight: total,
        }
    }

    /// Assign a country to each of `n` nodes using weighted random distribution.
    /// Uses the provided RNG for deterministic assignment.
    pub fn assign_countries(&self, n: usize, rng: &mut impl Rng) -> Vec<String> {
        (0..n)
            .map(|_| {
                let sample: f64 = rng.gen::<f64>() * self.total_weight;
                let mut cumulative = 0.0;
                for (i, &w) in self.weights.iter().enumerate() {
                    cumulative += w;
                    if sample <= cumulative {
                        return self.countries[i].clone();
                    }
                }
                self.countries.last().cloned().unwrap_or_default()
            })
            .collect()
    }

    pub fn country_count(&self) -> usize {
        self.countries.len()
    }
}
