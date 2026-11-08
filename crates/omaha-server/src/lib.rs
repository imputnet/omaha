//! Server for Chromium's update protocol (Omaha).

use std::collections::HashMap;
use std::hash::Hash;

/// Routes app IDs in an update check to the sources that answer them.
#[derive(Clone, Debug)]
pub struct Router<S> {
    routes: HashMap<String, S>,
}

/// One source's share of an update check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route<S> {
    pub source: S,
    /// Positions of this source's apps in the request.
    pub apps: Vec<usize>,
}

/// An update check split up by source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Split<S> {
    /// Sources in order of their first app in the request.
    pub routes: Vec<Route<S>>,
    /// Positions of apps no source knows.
    pub unknown: Vec<usize>,
}

impl<S: Clone + Eq + Hash> Router<S> {
    pub fn new() -> Self {
        Router {
            routes: HashMap::new(),
        }
    }

    pub fn route(mut self, appid: impl Into<String>, source: S) -> Self {
        self.routes.insert(appid.into(), source);
        self
    }

    /// Splits the app IDs of a request by source, keeping request order so
    /// answers can be merged back in place.
    pub fn split<'a>(&self, appids: impl IntoIterator<Item = &'a str>) -> Split<S> {
        let mut routes: Vec<Route<S>> = Vec::new();
        let mut index: HashMap<S, usize> = HashMap::new();
        let mut unknown = Vec::new();
        for (i, appid) in appids.into_iter().enumerate() {
            let Some(source) = self.routes.get(appid) else {
                unknown.push(i);
                continue;
            };
            let slot = *index.entry(source.clone()).or_insert_with(|| {
                routes.push(Route {
                    source: source.clone(),
                    apps: Vec::new(),
                });
                routes.len() - 1
            });
            routes[slot].apps.push(i);
        }
        Split { routes, unknown }
    }
}

impl<S: Clone + Eq + Hash> Default for Router<S> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_by_source_in_order() {
        let router = Router::new()
            .route("a", "local")
            .route("b", "upstream")
            .route("c", "local");
        let split = router.split(["b", "x", "a", "c", "y"]);
        assert_eq!(
            split.routes,
            vec![
                Route {
                    source: "upstream",
                    apps: vec![0]
                },
                Route {
                    source: "local",
                    apps: vec![2, 3]
                },
            ]
        );
        assert_eq!(split.unknown, vec![1, 4]);
    }

    #[test]
    fn empty() {
        let router: Router<u8> = Router::default();
        let split = router.split([]);
        assert!(split.routes.is_empty() && split.unknown.is_empty());
    }
}
