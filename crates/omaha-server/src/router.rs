use std::collections::HashMap;
use std::hash::Hash;

/// Routes app IDs in an update check to the sources that answer them.
#[derive(Clone, Debug)]
pub struct Router<S> {
    routes: HashMap<String, S>,
    fallback: Option<S>,
}

/// One source's share of an update check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route<S> {
    /// The source these apps go to.
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
    /// A router with no routes and no fallback, which puts every app in
    /// [`Split::unknown`].
    pub fn new() -> Self {
        Router {
            routes: HashMap::new(),
            fallback: None,
        }
    }

    /// Routes `appid` to `source`, replacing any earlier route for the same
    /// app ID.
    pub fn route(mut self, appid: impl Into<String>, source: S) -> Self {
        self.routes.insert(appid.into(), source);
        self
    }

    /// Routes every app ID without a route of its own to `source`.
    pub fn fallback(mut self, source: S) -> Self {
        self.fallback = Some(source);
        self
    }

    /// Whether `appid` has a route of its own, not just the fallback.
    pub fn is_routed(&self, appid: &str) -> bool {
        self.routes.contains_key(appid)
    }

    /// The source `appid` goes to: its own route, else the fallback.
    pub fn source(&self, appid: &str) -> Option<&S> {
        self.routes.get(appid).or(self.fallback.as_ref())
    }

    /// Splits the app IDs of a request by source, keeping request order so
    /// answers can be merged back in place.
    pub fn split<'a>(&self, appids: impl IntoIterator<Item = &'a str>) -> Split<S> {
        let mut routes: Vec<Route<S>> = Vec::new();
        let mut index: HashMap<S, usize> = HashMap::new();
        let mut unknown = Vec::new();
        for (i, appid) in appids.into_iter().enumerate() {
            let Some(source) = self.routes.get(appid).or(self.fallback.as_ref()) else {
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
    fn falls_back() {
        let router = Router::new().route("a", "local").fallback("upstream");
        let split = router.split(["x", "a", "y"]);
        assert_eq!(
            split.routes,
            vec![
                Route {
                    source: "upstream",
                    apps: vec![0, 2]
                },
                Route {
                    source: "local",
                    apps: vec![1]
                },
            ]
        );
        assert!(split.unknown.is_empty());
    }

    #[test]
    fn empty() {
        let router: Router<u8> = Router::default();
        let split = router.split([]);
        assert!(split.routes.is_empty() && split.unknown.is_empty());
    }
}
