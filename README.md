# Implémentation de CRYSTALS-Kyber en Python 

Ce dépôt contient une implémentation en Python pur de CRYSTALS-Kyber, suivant (au moment de l'écriture) la version la plus récente.
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
(v3.02)

## Avertissement

:warning: **En aucun cas ceci ne doit être utilisé pour une application cryptographique.** :warning:

Ce code n'est pas en temps constant et n'a pas été écrit pour être performant. 
Il a été écrit afin de pouvoir lire et comprendre les Algorithmes 1 à 9 dans la
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
Ceci se rapproche étroitement du code qui est visible dans kyber.py.

### KATs

Cette implémentation réussit actuellement tous les tests KAT de l'implémentation de référence.
Pour plus d'informations, consultez les tests unitaires dans[`test_kyber.py`](test_kyber.py).

**Note**: Il y a une divergence entre la spécification et l'implémentation de référence. 
Pour garantir que tous les tests KAT réussissent, 
je dois générer la clé publique avant les octets aléatoires $z = \mathcal{B}^{32}$ dans l'algorithme 7 de la
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
(v3.02).

### Dependences

À l'origine, il était prévu que cela n'ait aucune dépendance, cependant pour que cela fonctionne et réussisse les KATs, 
j'avais besoin d'un Générateur de Nombres Aléatoires Cryptographiquement Sécurisé (CSRNG) déterministe. 
L'implémentation de référence utilise AES256 CTR DRBG. J'ai implémenté cela dans aes256_ctr_drbg.py. 
Cependant, je n'ai pas implémenté AES lui-même, je l'importe plutôt depuis pycryptodome.
Pour installer les dépendances, exécutez pip -r install requirements."

Si vous êtes prêt à utiliser l'aléatoire du système (os.urandom), 
vous n'avez pas besoin de cette dépendance.

## Utilisation de kyber-p

Il y a trois fonctions exposées sur la classe Kyber qui sont destinées à être utilisées :

-Kyber.keygen(): génère une paire de clés (pk, sk)
-Kyber.enc(pk): génère un défi et une clé partagée (c, K)
-Kyber.dec(c, sk): génère la clé partagée K
Pour utiliser Kyber(), il doit être initialisé avec un dictionnaire des paramètres du protocole. 
Un exemple peut être vu dans DEFAULT_PARAMETERS.
#### Exemple

```python
>>> from kyber import Kyber512
>>> pk, sk = Kyber512.keygen()
>>> c, key = Kyber512.enc(pk)
>>> _key = Kyber512.dec(c, sk)
>>> assert key == _key
```

The above example would also work with `Kyber768` and `Kyber1024`.

### Benchmarks

**TODO**: Des meilleures mesures de performances ? Même si cela n'a jamais été une question de vitesse haha

For now, here are some approximate benchmarks:

|  1000 Iterations         | Kyber512 | Kyber768 | Kyber1024 |
|--------------------------|----------|----------|-----------|
| `KeyGen()`               |  6.868s  | 10.820s  | 16.172s   |
| `Enc()`                  | 10.677s  | 16.094s  | 22.341s   |
| `Dec()`                  | 16.822s  | 25.979s  | 33.524s   |

Tous les temps enregistrés ont été obtenus en utilisant un processeur 
Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz, 2501 MHz, 2 cœur(s), 4 processeur(s) logique(s)
 

## Projets Futurs

* Ajouter de la documentation sur la transformation NTT pour les polynômes
* Ajouter de la documentation sur le fonctionnement du DRBG et le paramétrage de la graine


## Discussion de l'Implementation

### Kyber

```
TODO:

Pour étendre la discussion sur la façon dont le travail avec Kyber fonctionne avec cette bibliothèque, vous pouvez inclure les éléments suivants :
```

### Polynomials

Le fichier polynomials.py contient les classes PolynomialRing et Polynomial. Cela met en œuvre l'anneau de polynômes univariés.
$$
R_q = \mathbb{F}_q[X] /(X^n + 1) 
$$

L'implémentation est inspirée par SageMath et vous pouvez créer l'anneau
$R_{11} = \mathbb{F}_{11}[X] /(X^8 + 1)$ de la manière suivante:

#### Example

```python
>>> R = PolynomialRing(11, 8)
>>> x = R.gen()
>>> f = 3*x**3 + 4*x**7
>>> g = R.random_element(); g
5 + x^2 + 5*x^3 + 4*x^4 + x^5 + 3*x^6 + 8*x^7
>>> f*g
8 + 9*x + 10*x^3 + 7*x^4 + 2*x^5 + 5*x^6 + 10*x^7
>>> f + f
6*x^3 + 8*x^7
>>> g - g
0
```

We additionally include functions for `PolynomialRing` and `Polynomial`
to move from bytes to polynomials (and back again). 

- `PolynomialRing`
  - `parse(bytes)` takes $3n$ bytes and produces a random polynomial in $R_q$
  - `decode(bytes, l)` takes $\ell n$ bits and produces a polynomial in $R_q$
  - `cbd(beta, eta)` takes $\eta \cdot n / 4$ bytes and produces a polynomial in $R_q$ with coefficents taken from a centered binomial distribution
- `Polynomial`
  - `self.encode(l)` takes the polynomial and returns a length $\ell n / 8$ bytearray
  
#### Example

```python
>>> R = PolynomialRing(11, 8)
>>> f = R.random_element()
>>> # If we do not specify `l` then it is computed for us (minimal value)
>>> f_bytes = f.encode()
>>> f_bytes.hex()
'06258910'
>>> R.decode(f_bytes) == f
True
>>> # We can also set `l` ourselves
>>> f_bytes = f.encode(l=10)
>>> f_bytes.hex()
'00180201408024010000'
>>> R.decode(f_bytes, l=10) == f
True
```

Lastly, we define a `self.compress(d)` and `self.decompress(d)` method for
polynomials following page 2 of the 
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)

$$
\textsf{compress}_q(x, d) = \lceil (2^d / q) \cdot x \rfloor \textrm{mod}^+ 2^d,
$$

$$
\textsf{decompress}_q(x, d) = \lceil (q / 2^d) \cdot x \rfloor.
$$

The functions `compress` and `decompress` are defined for the coefficients 
of a polynomial and a polynomial is (de)compressed by acting the function
on every coefficient. 
Similarly, an element of a module is (de)compressed by acting the
function on every polynomial.

#### Example

```python
>>> R = PolynomialRing(11, 8)
>>> f = R.random_element()
>>> f
9 + 3*x + 5*x^2 + 2*x^3 + 9*x^4 + 10*x^5 + 6*x^6 + x^7
>>> f.compress(1)
x + x^2 + x^6
>>> f.decompress(1)
6*x + 6*x^2 + 6*x^6
```

**Note**: compression is lossy! We do not get the same polynomial back 
by computing `f.compress(d).decompress(d)`. They are however *close*.
See the specification for more information.

### Number Theoretic Transform

```
TODO:

This is now handled by `NTTHelper` which is passed to `PolynomialRing`
and has functions which are accessed by `Polynomial`.

Talk about what is available, and how they are used.
```

### Modules

The file [`modules.py`](modules.py) contains the classes `Module` and `Matrix`.
A module is a generalisation of a vector space, where the field
of scalars is replaced with a ring. In the case of Kyber, we 
need the module with the ring $R_q$ as described above. 

`Matrix` allows elements of the module to be of size $m \times n$
but for Kyber, we only need vectors of length $k$ and square
matricies of size $k \times k$.

As an example of the operations we can perform with out `Module`
lets revisit the ring from the previous example:

#### Example

```python
>>> R = PolynomialRing(11, 8)
>>> x = R.gen()
>>>
>>> M = Module(R)
>>> # We create a matrix by feeding the coefficients to M
>>> A = M([[x + 3*x**2, 4 + 3*x**7], [3*x**3 + 9*x**7, x**4]])
>>> A
[    x + 3*x^2, 4 + 3*x^7]
[3*x^3 + 9*x^7,       x^4]
>>> # We can add and subtract matricies of the same size
>>> A + A
[  2*x + 6*x^2, 8 + 6*x^7]
[6*x^3 + 7*x^7,     2*x^4]
>>> A - A
[0, 0]
[0, 0]
>>> # A vector can be constructed by a list of coefficents
>>> v = M([3*x**5, x])
>>> v
[3*x^5, x]
>>> # We can compute the transpose
>>> v.transpose()
[3*x^5]
[    x]
>>> v + v
[6*x^5, 2*x]
>>> # We can also compute the transpose in place
>>> v.transpose_self()
[3*x^5]
[    x]
>>> v + v
[6*x^5]
[  2*x]
>>> # Matrix multiplication follows python standards and is denoted by @
>>> A @ v
[8 + 4*x + 3*x^6 + 9*x^7]
[        2 + 6*x^4 + x^5]
```

We also carry through `Matrix.encode()` and 
`Module.decode(bytes, n_rows, n_cols)` 
which simply use the above functions defined for polynomials and run for each
element.

#### Example

We can see how encoding / decoding a vector works in the following example.
Note that we can swap the rows/columns to decode bytes into the transpose
when working with a vector.

```python
>>> R = PolynomialRing(11, 8)
>>> M = Module(R)
>>> v = M([R.random_element() for _ in range(2)])
>>> v_bytes = v.encode()
>>> v_bytes.hex()
'd'
>>> M.decode(v_bytes, 1, 2) == v
True
>>> v_bytes = v.encode(l=10)
>>> v_bytes.hex()
'a014020100103004000040240a03009030080200'
>>> M.decode(v_bytes, 1, 2, l=10) == v
True
>>> M.decode(v_bytes, 2, 1, l=10) == v.transpose()
True
>>> # We can also compress and decompress elements of the module
>>> v
[5 + 10*x + 4*x^2 + 2*x^3 + 8*x^4 + 3*x^5 + 2*x^6, 2 + 9*x + 5*x^2 + 3*x^3 + 9*x^4 + 3*x^5 + x^6 + x^7]
>>> v.compress(1)
[1 + x^2 + x^4 + x^5, x^2 + x^3 + x^5]
>>> v.decompress(1)
[6 + 6*x^2 + 6*x^4 + 6*x^5, 6*x^2 + 6*x^3 + 6*x^5]
```

## Baby Kyber

A great resource for learning Kyber is available at
[Approachable Cryptography](https://cryptopedia.dev/posts/kyber/).

We include code corresponding to their example in `baby_kyber.py`.
