import os
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from polynomials import *
from modules import *
from ntt_helper import NTTHelperKyber
try:
    from aes256_ctr_drbg import AES256_CTR_DRBG
except ImportError as e:
    print("Il semble qu'il y ait une erreur lors de l'importation de AES CTR DRBG. Avez-vous essayé d'installer les dépendances requises ??")
    print(f"ImportError: {e}\n")
    print("Kyber fonctionnera parfaitement bien avec l'aléatoire système")
    
    
DEFAULT_PARAMETERS = {
    "kyber_512" : {
        "n" : 256,
        "k" : 2,
        "q" : 3329,
        "eta_1" : 3,
        "eta_2" : 2,
        "du" : 10,
        "dv" : 4,
    },
    "kyber_768" : {
        "n" : 256,
        "k" : 3,
        "q" : 3329,
        "eta_1" : 2,
        "eta_2" : 2,
        "du" : 10,
        "dv" : 4,
    },
    "kyber_1024" : {
        "n" : 256,
        "k" : 4,
        "q" : 3329,
        "eta_1" : 2,
        "eta_2" : 2,
        "du" : 11,
        "dv" : 5,
    }
}

class Kyber:
    def __init__(self, parameter_set):
        self.n = parameter_set["n"]
        self.k = parameter_set["k"]
        self.q = parameter_set["q"]
        self.eta_1 = parameter_set["eta_1"]
        self.eta_2 = parameter_set["eta_2"]
        self.du = parameter_set["du"]
        self.dv = parameter_set["dv"]
        
        self.R = PolynomialRing(self.q, self.n, ntt_helper=NTTHelperKyber)
        self.M = Module(self.R)
        
        self.drbg = None
        self.random_bytes = os.urandom
        
    def set_drbg_seed(self, seed):
        """
        Définir la graine bascule la source d'entropie de os.urandom à AES256 CTR DRBG
        
        Remarque : nécessite pycryptodome pour l'implémentation AES. 
        (Il semblait excessif de coder mon propre AES pour Kyber.)
        """
        self.drbg = AES256_CTR_DRBG(seed)
        self.random_bytes = self.drbg.random_bytes

    def reseed_drbg(self, seed):
        """
        Réinitialise le DRBG, erreurs si un DRBG n'est pas défini.
        
        Remarque : nécessite pycryptodome pour AES impl.
        (Cela semblait exagéré de coder mon propre AES pour Kyber)
        """
        if self.drbg is None:
            raise Warning(f"Cannot reseed DRBG without first initialising. Try using `set_drbg_seed`")
        else:
            self.drbg.reseed(seed)
        
    @staticmethod
    def _xof(bytes32, a, b, length):
        """
        XOF: B^* x B x B -> B*
        """
        input_bytes = bytes32 + a + b
        if len(input_bytes) != 34:
            raise ValueError(f"Input bytes should be one 32 byte array and 2 single bytes.")
        return shake_128(input_bytes).digest(length)
        
    @staticmethod
    def _h(input_bytes):
        """
        H: B* -> B^32
        """
        return sha3_256(input_bytes).digest()
    
    @staticmethod  
    def _g(input_bytes):
        """
        G: B* -> B^32 x B^32
        """
        output = sha3_512(input_bytes).digest()
        return output[:32], output[32:]
    
    @staticmethod  
    def _prf(s, b, length):
        """
        PRF: B^32 x B -> B^*
        """
        input_bytes = s + b
        if len(input_bytes) != 33:
            raise ValueError(f"Les octets d'entrée devraient être un tableau de 32 octets et un seul octet.")
        return shake_256(input_bytes).digest(length)
    
    @staticmethod
    def _kdf(input_bytes, length):
        """
        KDF: B^* -> B^*
        """
        return shake_256(input_bytes).digest(length)
    
    def _generate_error_vector(self, sigma, eta, N, is_ntt=False):
        """
        Fonction d'assistance qui génère un élément dans le
        module de la distribution binomiale centrée.
        """
        elements = []
        for i in range(self.k):
            input_bytes = self._prf(sigma,  bytes([N]), 64*eta)
            poly = self.R.cbd(input_bytes, eta, is_ntt=is_ntt)
            elements.append(poly)
            N = N + 1
        v = self.M(elements).transpose()
        return v, N
        
    def _generate_matrix_from_seed(self, rho, transpose=False, is_ntt=False):
        """
        Fonction d'assistance qui génère un élément de taille
        k x k à partir d'une graine `rho`.
        
        Lorsque `transpose` est défini sur True, la matrice A est
        construit comme la transposition.
        """
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                if transpose:
                    input_bytes = self._xof(rho, bytes([i]), bytes([j]), 3*self.R.n)
                else:
                    input_bytes = self._xof(rho, bytes([j]), bytes([i]), 3*self.R.n)
                aij = self.R.parse(input_bytes, is_ntt=is_ntt)
                row.append(aij)
            A.append(row)
        return self.M(A)
        
    def _cpapke_keygen(self):
        """
        Algorithm 4 (Génération de clé)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Saisir:
            Aucun
        Sortir:
            Clé secrète (12*k*n) / 8 octets
            Clé publique (12*k*n) / 8 + 32 octets
        """
        # Générer une valeur aléatoire, un hachage et un fractionnement
        d = self.random_bytes(32)
        rho, sigma = self._g(d)
        # Définir le compteur pour PRF
        N = 0
        
        # Générer la matrice A ∈ R^kxk
        A = self._generate_matrix_from_seed(rho, is_ntt=True)
        
        # Générer le vecteur d'erreur s ∈ R^k
        s, N = self._generate_error_vector(sigma, self.eta_1, N)
        s.to_ntt()
        
        # Générer le vecteur d'erreur e ∈ R^k
        e, N = self._generate_error_vector(sigma, self.eta_1, N)
        e.to_ntt() 
                           
        # Construire la clé publique
        t = (A @ s).to_montgomery() + e
        
        # Réduire les vecteurs mod^+ q
        t.reduce_coefficents()
        s.reduce_coefficents()
        
        # Encoder les éléments en octets et renvoyer
        pk = t.encode(l=12) + rho
        sk = s.encode(l=12)
        return pk, sk
        
    def _cpapke_enc(self, pk, m, coins):
        """
        Algorithm 5 (Encryption)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
       Saisir:
            pk : clé publique
            m : message ∈ B^32
            pièces : pièces aléatoires ∈ B^32
        Sortir:
            c : texte chiffré
        """
        N = 0
        rho = pk[-32:]
        
        tt = self.M.decode(pk, 1, self.k, l=12, is_ntt=True)        
        
        # Encoder le message sous forme de polynôme
        m_poly = self.R.decode(m, l=1).decompress(1)
        
        # Générer la matrice A^T ∈ R^(kxk)
        At = self._generate_matrix_from_seed(rho, transpose=True, is_ntt=True)
        
        # Générer le vecteur d'erreur r ∈ R^k
        r, N = self._generate_error_vector(coins, self.eta_1, N)
        r.to_ntt()
        
        # Générer le vecteur d'erreur e1 ∈ R^k
        e1, N = self._generate_error_vector(coins, self.eta_2, N)
        
        # Générer le polynôme d'erreur e2 ∈ R
        input_bytes = self._prf(coins,  bytes([N]), 64*self.eta_2)
        e2 = self.R.cbd(input_bytes, self.eta_2)
        
        # Module/Arithmétique polynomiale
        u = (At @ r).from_ntt() + e1
        v = (tt @ r)[0][0].from_ntt()
        v = v + e2 + m_poly
        
        # Texte chiffré en octets
        c1 = u.compress(self.du).encode(l=self.du)
        c2 = v.compress(self.dv).encode(l=self.dv)
        
        return c1 + c2
    
    def _cpapke_dec(self, sk, c):
        """
        Algorithm 6 (Decryption)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Saisir:
            sk : clé publique
            c : message ∈ B^32
        Sortir:
            m : message ∈ B^32
        """
        # Diviser le texte chiffré en vecteurs
        index = self.du * self.k * self.R.n // 8
        c2 = c[index:]
        
        # Récupérez le vecteur u et convertissez-le en forme NTT
        u = self.M.decode(c, self.k, 1, l=self.du).decompress(self.du)
        u.to_ntt()
        
        # Récupérer le polynôme v
        v = self.R.decode(c2, l=self.dv).decompress(self.dv)
        
        # s_transpose (déjà sous forme NTT)
        st = self.M.decode(sk, 1, self.k, l=12, is_ntt=True)
        
        # Récupérer le message sous forme de polynôme
        m = (st @ u)[0][0].from_ntt()
        m = v - m
        
        # Renvoie le message sous forme d'octets
        return m.compress(1).encode(l=1)
    
    def keygen(self):
        """
        Algorithm 7 (CCA KEM KeyGen)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
       Sortir:
            pk : clé publique
            sk : clé secrète
            
        """
        # Notez que bien que les gens du papier z alors
        # pk, sk, l'implémentation fait ça
        # moyen de contournement, ce qui est important pour le déterminisme
        # le hasard...
        pk, _sk = self._cpapke_keygen()
        z = self.random_bytes(32)
        
        # sk = sk' || pk || H(pk) || z
        sk = _sk + pk + self._h(pk) + z
        return pk, sk
        
    def enc(self, pk, key_length=32):
        """
        Algorithm 8 (CCA KEM Encapsulation)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Saisir:
            pk : clé publique
        Sortir:
            c : texte chiffré
            K : clé partagée
        """
        m = self.random_bytes(32)
        m_hash = self._h(m)
        Kbar, r = self._g(m_hash + self._h(pk))
        c = self._cpapke_enc(pk, m_hash, r)
        K = self._kdf(Kbar + self._h(c), key_length)
        return c, K

    def dec(self, c, sk, key_length=32):
        """
        Algorithm 9 (CCA KEM Decapsulation)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Saisir:
            c : texte chiffré
            sk : clé secrète
        Sortir:
            K : clé partagée
        """
        # Extraire les valeurs de `sk`
        # sk = _sk || pk || H(pk) || z
        index = 12 * self.k * self.R.n // 8
        _sk =  sk[:index]
        pk = sk[index:-64]
        hpk = sk[-64:-32]
        z = sk[-32:]
        
        # Decrypt the ciphertext
        _m = self._cpapke_dec(_sk, c)
        
        # Decapsulation
        _Kbar, _r = self._g(_m + hpk)
        _c = self._cpapke_enc(pk, _m, _r)
        
        # si la décapsulation a réussi, retournez K
        if c == _c:
            return self._kdf(_Kbar + self._h(c), key_length)
        # Échec de la décapsulation... renvoie une valeur aléatoire
        return self._kdf(z + self._h(c), key_length)

# Initialisez avec les paramètres par défaut pour une importation facile
Kyber512 = Kyber(DEFAULT_PARAMETERS["kyber_512"])
Kyber768 = Kyber(DEFAULT_PARAMETERS["kyber_768"])
Kyber1024 = Kyber(DEFAULT_PARAMETERS["kyber_1024"])
    
