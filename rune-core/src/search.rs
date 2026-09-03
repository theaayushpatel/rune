use crate::models::OtpAccount;
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;

/// A fuzzy search match result with scoring.
#[derive(Debug, Clone)]
pub struct SearchResult<'a> {
    pub account: &'a OtpAccount,
    pub score: i64,
}

/// In-memory fuzzy matcher for OTP accounts.
pub struct AccountSearcher {
    matcher: SkimMatcherV2,
}

impl Default for AccountSearcher {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountSearcher {
    pub fn new() -> Self {
        Self {
            matcher: SkimMatcherV2::default(),
        }
    }

    /// Search and rank a slice of accounts against a query.
    ///
    /// If query is empty, returns all accounts with score 0 in original order.
    pub fn search<'a>(&self, accounts: &'a [OtpAccount], query: &str) -> Vec<SearchResult<'a>> {
        let query = query.trim();
        if query.is_empty() {
            return accounts
                .iter()
                .map(|account| SearchResult { account, score: 0 })
                .collect();
        }

        let mut results: Vec<SearchResult<'a>> = accounts
            .iter()
            .filter_map(|account| {
                let mut best_score: Option<i64> = None;

                // 1. Search issuer
                if let Some(issuer) = &account.issuer {
                    if let Some(s) = self.matcher.fuzzy_match(issuer, query) {
                        best_score = Some(s + 20); // Prioritize issuer matches
                    }
                }

                // 2. Search name/username
                if let Some(s) = self.matcher.fuzzy_match(&account.name, query) {
                    best_score = Some(best_score.map_or(s, |prev| prev.max(s)));
                }

                // 3. Search combined display label (e.g. "GitHub (alice)")
                let combined = account.display_label();
                if let Some(s) = self.matcher.fuzzy_match(&combined, query) {
                    best_score = Some(best_score.map_or(s, |prev| prev.max(s)));
                }

                // 4. Search notes if present
                if let Some(note) = &account.note {
                    if let Some(s) = self.matcher.fuzzy_match(note, query) {
                        best_score = Some(best_score.map_or(s, |prev| prev.max(s)));
                    }
                }

                best_score.map(|score| SearchResult { account, score })
            })
            .collect();

        // Sort descending by score
        results.sort_by(|a, b| b.score.cmp(&a.score));
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Algorithm, OtpType};

    #[test]
    fn test_search_scoring() {
        let accounts = vec![
            OtpAccount {
                id: "1".into(),
                name: "alice@gmail.com".into(),
                issuer: Some("Google".into()),
                secret: "JBSWY3DPEHPK3PXP".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                otp_type: OtpType::Totp,
                counter: None,
                icon: None,
                note: None,
            },
            OtpAccount {
                id: "2".into(),
                name: "alice".into(),
                issuer: Some("GitHub".into()),
                secret: "JBSWY3DPEHPK3PXP".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                otp_type: OtpType::Totp,
                counter: None,
                icon: None,
                note: None,
            },
        ];

        let searcher = AccountSearcher::new();

        let res1 = searcher.search(&accounts, "git");
        assert_eq!(res1.len(), 1);
        assert_eq!(res1[0].account.id, "2");

        let res2 = searcher.search(&accounts, "alice");
        assert_eq!(res2.len(), 2);

        let res_empty = searcher.search(&accounts, "");
        assert_eq!(res_empty.len(), 2);
    }
}
