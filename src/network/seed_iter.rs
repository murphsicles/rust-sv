#![allow(deprecated)]

use dns_lookup::lookup_host;
use log::{error, info};
use rand::{thread_rng, Rng};
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
        let mut rng = thread_rng();
        let random_offset = rng.gen_range(0..100);
        Self {
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
        loop {
            if self.seed_index >= self.seeds.len() {
                return None;
            }
            if self.nodes.is_empty() {
                let i = (self.seed_index + self.random_offset) % self.seeds.len();
                info!("Looking up DNS: {}", self.seeds[i]);
                match lookup_host(&self.seeds[i]) {
                    Ok(ip_list) => {
                        let ip_vec: Vec<IpAddr> = ip_list.collect(); // Convert iterator to Vec
                        if ip_vec.is_empty() {
                            error!("DNS lookup for {} returned no IPs", self.seeds[i]);
                            self.seed_index += 1;
                            continue;
                        }
                        self.nodes = ip_vec; // Assign Vec to self.nodes
                    }
                    Err(e) => {
                        error!("Failed to look up DNS {}: {}", self.seeds[i], e);
                        self.seed_index += 1;
                        continue;
                    }
                }
            }
            let i = (self.node_index + self.random_offset) % self.nodes.len();
            self.node_index += 1;
            if self.node_index >= self.nodes.len() {
                self.node_index = 0;
                self.seed_index += 1;
                self.nodes.clear();
            }
            return Some((self.nodes[i], self.port));
        }
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
