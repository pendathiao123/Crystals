"""
Il s'agit d'une implémentation simplifiée de Kyber qui suit
https://cryptopedia.dev/posts/kyber/

Comme les polynômes sont donnés précisément dans l'article de blog,
tous les calculs sont effectués en appelant `polynomes` et
`modules` plutôt que `Kyber` lui-même.
"""

from polynomials import *  # Importation des fonctions de manipulation des polynômes
from modules import *  # Importation des fonctions de manipulation des modules

def keygen():
    # La randomisation est fixée pour l'exemple
    # Génère une clé secrète qui
    # est un vecteur avec des éléments 
    # extraits d'une distribution binomiale centrée
    s0 = R([0,1,-1,-1])
    s1 = R([0,-1,0,-1])
    s = M([s0,s1]).transpose()

    # La randomisation est fixée pour l'exemple
    # Génère une matrice 2x2 avec 
    # des éléments pris aléatoirement dans
    # R_q
    A00 = R([11,16,16,6])
    A01 = R([3,6,4,9])
    A10 = R([1,10,3,5])
    A11 = R([15,9,1,6])
    A = M([[A00, A01],[A10, A11]])

    # La randomisation est fixée pour l'exemple
    # génère un vecteur aléatoire `e` à partir de
    # distribution binomiale
    e0 = R([0,0,1,0])
    e1 = R([0,-1,1,0])
    e = M([e0,e1]).transpose()

    # Calcule `t` à partir de l'exemple
    t = A @ s + e
    
    # Vérifie par rapport à l'article de blog
    assert t == M([R([7,0,15,16]),R([6,11,12,10])]).transpose()
    return (A, t), s

def enc(m, public_key):
    # randomisation fixée pour l'exemple
    # génère un vecteur aléatoire `r` à partir de
    # distribution binomiale
    r0 = R([0,0,1,-1]) 
    r1 = R([-1,0,1,1])
    r = M([r0, r1]).transpose()
    
    # randomisation fixée pour l'exemple
    # génère un vecteur aléatoire `e_1` à partir de
    # distribution binomiale
    e_10 = R([0,1,1,0])
    e_11 = R([0,0,1,0])
    e_1 = M([e_10, e_11]).transpose()
    
    # randomisation fixée pour l'exemple
    # génère un polynôme aléatoire `e_2` à partir de
    # distribution binomiale
    e_2 = R([0,0,-1,-1])

    A, t = public_key
    poly_m = R.decode(m).decompress(1)
    # Vérifie par rapport à l'article de blog
    assert poly_m == R([9,9,0,9])
    
    u = A.transpose() @ r + e_1
    # Vérifie par rapport à l'article de blog
    assert u == M([R([3,10,11,11]), R([11,13,4,4])]).transpose()
    
    # Erreur de frappe dans l'article de blog, nous devons utiliser
    # `- m` plutôt que `+ m` pour que les valeurs correspondent
    v = (t.transpose() @ r)[0][0] + e_2 - poly_m  
    assert v == R([15, 8 , 6, 7])
    return u, v

def dec(u, v, s):
    m_n = v - (s.transpose() @ u)[0][0]
    # Vérifie par rapport à l'article de blog
    assert m_n == R([5,7,14,7])
    # Vérifie par rapport à l'article de blog
    m_n_reduced = m_n.compress(1)
    assert m_n_reduced == R([1,1,0,1])
    return m_n_reduced.encode(l=2)
    
if __name__ == '__main__':
    R = PolynomialRing(17, 4)
    M = Module(R)
    # Notre codage de polynômes suit les spécifications
    # de Kyber. Nous encodons donc l'octet `b'E'` pour obtenir le
    # polynôme de l'article de blog
    # >>> R.decode(bytes([69]))
    # 1 + x + x^3
    m = bytes([69])
    assert R.decode(m) == R([1,1,0,1])
    # Génère une paire de clés
    pub, priv = keygen()
    print("cle publique ():",pub)
    print("cle privee:",priv)
    # Chiffre le message
    u, v = enc(m, pub)
    print("Valeur de u: ",u)
    print("Valeur de v: ",v)
    # Déchiffre le message
    n = dec(u, v, priv)
    assert n == m
    # Affiche le résultat du déchiffrement
    print("Message dechiffre:", n)
