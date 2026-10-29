"""Coppersmith small roots of a monic univariate polynomial modulo a divisor of N.

This mirrors Sage's ``small_roots`` (the lattice construction follows Alexander
May's thesis) but extracts the integer root of the LLL-reduced polynomial with
PARI instead of NTL. Sage's ``f.roots()`` factors over ZZ with NTL for degrees
below 30, and NTL's ``ZZX_factor`` segfaults on some of the high-degree,
large-coefficient polynomials these lattices produce. The lattice and the
choice of m, t and X are identical to Sage, so results and bounds match it
wherever Sage does not crash.
"""

from __future__ import annotations

from sage.all import ZZ, Matrix, RR


def _integer_roots(poly, bound):
    """Integer roots r of the ZZ polynomial ``poly`` with |r| <= bound, via PARI."""
    if poly.is_zero():
        return []
    primitive = poly // poly.content()
    roots = []
    for factor, _ in primitive._factor_pari():  # bypasses the NTL factor path
        if factor.degree() == 1:
            a0, a1 = factor[0], factor[1]  # factor = a1*x + a0
            if a1 and a0 % a1 == 0:
                r = -a0 // a1
                if abs(r) <= bound:
                    roots.append(r)
    return roots


def small_roots(f, X=None, beta=1.0, epsilon=None):
    """Roots x0 of monic ``f`` with |x0| <= X and f(x0) == 0 mod a divisor b >= N^beta of N.

    ``f`` is a polynomial over ``Zmod(N)``. Returns the roots as ``Zmod(N)``
    elements, like Sage's ``small_roots``.
    """
    N = f.parent().characteristic()
    if not f.is_monic():
        raise ArithmeticError("Polynomial must be monic.")
    beta = RR(beta)
    if beta <= 0.0 or beta > 1.0:
        raise ValueError("0.0 < beta <= 1.0 not satisfied.")

    ZmodN = f.base_ring()
    fZ = f.change_ring(ZZ)
    x = fZ.parent().gen()
    delta = fZ.degree()

    if epsilon is None:
        epsilon = beta / 8
    m = max(beta**2 / (delta * epsilon), 7 * beta / delta).ceil()
    t = int((delta * m * (1 / beta - 1)).floor())
    if X is None:
        X = (0.5 * N ** (beta**2 / delta - epsilon)).ceil()
    X = ZZ(X)

    # Shift polynomials, all with x0 as a root modulo N^m.
    g = [x**j * N ** (m - i) * fZ**i for i in range(m) for j in range(delta)]
    g.extend(x**i * fZ**m for i in range(t))

    B = Matrix(ZZ, len(g), delta * m + t)
    for row in range(B.nrows()):
        for col in range(g[row].degree() + 1):
            B[row, col] = g[row][col] * X**col
    B = B.LLL()

    # First reduced vector back to a polynomial (undo the X**col scaling).
    G = sum(ZZ(B[0, col] // X**col) * x**col for col in range(B.ncols()))

    Nbeta = N**beta
    roots = []
    for r in _integer_roots(G, X):
        if N.gcd(ZZ(f(ZmodN(r)))) >= Nbeta:  # keep only roots modulo a large enough divisor
            roots.append(ZmodN(r))
    return roots
