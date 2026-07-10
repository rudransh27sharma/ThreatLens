from model.features import (
    count_special_chars,
    domain_age_days,
    extract_all_features,
    generic_greeting,
    grammar_error_density,
    has_https,
    has_ip_address,
    has_suspicious_keywords_in_domain,
    link_text_mismatch,
    num_subdomains,
    requests_sensitive_info,
    sender_domain_mismatch,
    urgency_score,
    url_length,
    uses_url_shortener,
)


def test_url_length_normal_and_malformed():
    assert url_length("https://example.com") == 19
    assert url_length(None) == 0


def test_num_subdomains_normal_and_malformed():
    assert num_subdomains("https://login.secure.example.com/path") == 2
    assert num_subdomains(None) == 0


def test_has_ip_address_normal_and_malformed():
    assert has_ip_address("http://192.168.0.1/login") is True
    assert has_ip_address(None) is False


def test_uses_url_shortener_normal_and_malformed():
    assert uses_url_shortener("https://bit.ly/abc") is True
    assert uses_url_shortener(None) is False


def test_has_https_normal_and_malformed():
    assert has_https("https://example.com") is True
    assert has_https(None) is False


def test_count_special_chars_normal_and_malformed():
    assert count_special_chars("https://example.com/a-b//@x") == 3
    assert count_special_chars(None) == 0


def test_has_suspicious_keywords_in_domain_normal_and_malformed():
    assert has_suspicious_keywords_in_domain("https://secure-login.example.com") is True
    assert has_suspicious_keywords_in_domain(None) is False


def test_domain_age_days_normal_and_malformed():
    assert domain_age_days("not a domain") is None
    assert domain_age_days(None) is None


def test_urgency_score_normal_and_malformed():
    assert urgency_score("Act now. Final notice.") == 2
    assert urgency_score(None) == 0


def test_requests_sensitive_info_normal_and_malformed():
    assert requests_sensitive_info("Send your password and OTP.") is True
    assert requests_sensitive_info(None) is False


def test_generic_greeting_normal_and_malformed():
    assert generic_greeting("Dear Customer, please review this.") is True
    assert generic_greeting("Hi Priya, your statement is ready.") is False
    assert generic_greeting(None) is False


def test_link_text_mismatch_normal_and_malformed():
    assert link_text_mismatch("Visit [PayPal](https://evil-login.example.com)") is True
    assert link_text_mismatch(None) is False


def test_grammar_error_density_normal_and_malformed():
    assert grammar_error_density("hello world!!  Review now...") > 0
    assert grammar_error_density(None) == 0.0


def test_sender_domain_mismatch_normal_and_malformed():
    assert sender_domain_mismatch("PayPal alert", "PayPal", "security.evil.com") is True
    assert sender_domain_mismatch("PayPal alert", "PayPal", None) is False


def test_extract_all_features_by_type_and_malformed():
    url_features = extract_all_features("https://secure-login.example.com", "url")
    assert "url_length" in url_features
    assert "urgency_score" not in url_features

    text_features = extract_all_features("Dear Customer, act now.", "email")
    assert "urgency_score" in text_features
    assert "url_length" not in text_features

    assert extract_all_features("anything", "unknown") == {}
