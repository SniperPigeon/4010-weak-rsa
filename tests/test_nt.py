from rsaexp.attacks.nt import crt, extended_gcd, integer_nth_root, int_to_text, modinv, text_to_int


def test_extended_gcd_week6_example():
    g, x, y = extended_gcd(973, 301)
    assert g == 7
    assert 973 * x + 301 * y == 7


def test_modinv_week6_example():
    assert modinv(9, 14) == 11


def test_crt_week6_example():
    x, modulus = crt([4, 3], [5, 7])
    assert modulus == 35
    assert x == 24


def test_integer_cube_root_exact_and_not():
    root, exact = integer_nth_root(27, 3)
    assert root == 3 and exact
    root, exact = integer_nth_root(28, 3)
    assert root == 3 and not exact


def test_text_roundtrip():
    assert int_to_text(text_to_int("Pay Alice 100")) == "Pay Alice 100"
