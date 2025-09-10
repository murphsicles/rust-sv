use dns_lookup::lookup_host;
use log::{error, info};
use rand::{Rng, rng, seq::SliceRandom};
use std::net::IpAddr;

#[derive(Clone, Debug)]
pub struct SeedIter<'a> {
    pub port: u16,
    seeds: &'a [String],
    nodes: Vec<IpAddr>,
    seed_index: usize,
    node_index: usize,
    random_offset: usize,
}

impl<'a> SeedIter<'a> {
    pub fn new(seeds: &'a [String], port: u16) -> Self {
        let mut rng = rng();
        let random_offset = rng.random_range(0..100);
        SeedIter {
            port,
            seeds,
            nodes: Vec::new(),
            seed_index: 0,
            node_index: 0,
            random_offset,
        }
    }
}

impl<'a> Iterator for SeedIter<'a> {
    type Item = (IpAddr, u16);

    fn next(&mut self) -> Option<Self::Item> {
        while self.seed_index < self.seeds.len() {
            if self.nodes.is_empty() {
                let i = (self.seed_index + self.random_offset) % self.seeds.len();
                info!("Looking up DNS: {}", self.seeds[i]);
                match lookup_host(&self.seeds[i]) {
                    Ok(ip_iter) => {
                        let mut ip_vec: Vec<IpAddr> = ip_iter.into_iter().collect();
                        if ip_vec.is_empty() {
                            error!("DNS lookup for {} returned no IPs", self.seeds[i]);
                            self.seed_index += 1;
                            continue;
                        }
                        ip_vec.shuffle(&mut rng());
                        self.nodes = ip_vec;
                        self.node_index = 0;
                    }
                    Err(e) => {
                        error!("Failed to look up DNS {}: {}", self.seeds[i], e);
                        self.seed_index += 1;
                        continue;
                    }
                }
            }
            if self.node_index < self.nodes.len() {
                let ip = self.nodes[self.node_index];
                self.node_index += 1;
                if self.node_index >= self.nodes.len() {
                    self.nodes.clear();
                    self.seed_index += 1;
                    self.node_index = 0;
                }
                return Some((ip, self.port));
            } else {
                self.nodes.clear();
                self.seed_index += 1;
                self.node_index = 0;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_iter_empty_seeds() {
        let seeds: Vec<String> = vec![];
        let mut iter = SeedIter::new(&seeds, 8333);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_seed_iter_invalid_seed() {
        let seeds = vec!["invalid.dns.seed".to_string()];
        let mut iter = SeedIter::new(&seeds, 8333);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_seed_iter_random_offset() {
        let seeds = vec!["seed.bitcoinsv.io".to_string()];
        let iter1 = SeedIter::new(&seeds, 8333);
        let iter2 = SeedIter::new(&seeds, 8333);
        assert_ne!(iter1.random_offset, iter2.random_offset);
    }
}
