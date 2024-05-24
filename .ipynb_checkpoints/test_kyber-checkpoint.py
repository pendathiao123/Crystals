import unittest
import os
from kyber import Kyber512, Kyber768, Kyber1024
from aes256_ctr_drbg import AES256_CTR_DRBG

def parse_kat_data(data):
    parsed_data = {}
    count_blocks = data.split('\n\n')
    for block in count_blocks[1:-1]:
        block_data = block.split('\n')
        count, seed, pk, sk, ct, ss = [line.split(" = ")[-1] for line in block_data]
        parsed_data[count] = {
            "seed": bytes.fromhex(seed),
            "pk": bytes.fromhex(pk),
            "sk": bytes.fromhex(sk),
            "ct": bytes.fromhex(ct),
            "ss": bytes.fromhex(ss),   
        }
    return parsed_data
    
class TestKyber(unittest.TestCase):
    """
    Testez les niveaux Kyber pour les utilisateurs internes
    cohérence en générant des paires de clés
    et des secrets partagés.
    """

    def generic_test_kyber(self, Kyber, count):
        for _ in range(count):
            pk, sk = Kyber.keygen()
            for _ in range(count):
                c, key = Kyber.enc(pk)
                _key = Kyber.dec(c, sk)
                self.assertEqual(key, _key)
    
    def test_kyber512(self):
        self.generic_test_kyber(Kyber512, 5)
        
    def test_kyber768(self):
        self.generic_test_kyber(Kyber768, 5)
        
    def test_kyber1024(self):
        self.generic_test_kyber(Kyber1024, 5)
                
class TestKyberDeterministic(unittest.TestCase):
    """
    Assurez-vous que le DRBG déterministe est déterministe !
    
    Utilise AES256 CTR DRBG pour le caractère aléatoire.
    Remarque : nécessite pycryptodome pour AES impl.
    """
    
    def generic_test_kyber_deterministic(self, Kyber, count):
        """
        Nous générons d’abord cinq paires pk,sk
        de la même graine et assurez-vous
        ils sont tous pareils
        """
        seed = os.urandom(48)
        pk_output = []
        for _ in range(count):
            Kyber.set_drbg_seed(seed)
            pk, sk = Kyber.keygen()
            pk_output.append(pk + sk)
        self.assertEqual(len(pk_output), 5)
        self.assertEqual(len(set(pk_output)), 1)

        """
        Maintenant, étant donné une paire de clés fixe, assurez-vous
        que c,key sont les mêmes pour une graine fixe
        """
        key_output = []
        seed = os.urandom(48)
        pk, sk = Kyber.keygen()
        for _ in range(count):
            Kyber.set_drbg_seed(seed)
            c, key = Kyber.enc(pk)
            _key = Kyber.dec(c, sk)
            # Check key derivation works
            self.assertEqual(key, _key)
            key_output.append(c + key)
        self.assertEqual(len(key_output), count)
        self.assertEqual(len(set(key_output)), 1)
        
    def test_kyber512_deterministic(self):
        self.generic_test_kyber_deterministic(Kyber512, 5)
    
    def test_kyber768_deterministic(self):
        self.generic_test_kyber_deterministic(Kyber768, 5)
    
    def test_kyber1024_deterministic(self):
        self.generic_test_kyber_deterministic(Kyber1024, 5)
        

class TestKnownTestValuesDRBG(unittest.TestCase):
    """
    Nous savons comment les graines du KAT sont générées, donc
    vérifions par rapport à notre propre implémentation.
    
    Nous n'avons besoin de tester qu'un seul fichier, car les graines sont les
    même chose dans les trois fichiers.
    """
    def test_kyber512_known_answer_seed(self):
        # Configurer DRBG pour générer des graines
        entropy_input = bytes([i for i in range(48)])
        rng = AES256_CTR_DRBG(entropy_input)
        
        with open("assets/PQCkemKAT_1632.rsp") as f:
            # extraire les données de KAT
            kat_data_512 = f.read()
            parsed_data = parse_kat_data(kat_data_512)
            # Vérifiez que toutes les graines correspondent
            for data in parsed_data.values():
                seed = data["seed"]
                self.assertEqual(seed, rng.random_bytes(48))
    
class TestKnownTestValues(unittest.TestCase): 
    def generic_test_kyber_known_answer(self, Kyber, filename):
        with open(filename) as f:
            kat_data = f.read()
            parsed_data = parse_kat_data(kat_data)
            
            for data in parsed_data.values():
                seed, pk, sk, ct, ss = data.values()
                
                # Semer DRBG avec des graines KAT
                Kyber.set_drbg_seed(seed)
                
                # Affirmer les correspondances keygen
                _pk, _sk = Kyber.keygen()
                self.assertEqual(pk, _pk)
                self.assertEqual(sk, _sk)
                
                # Affirmer les correspondances d'encapsulation
                _ct, _ss = Kyber.enc(_pk)
                self.assertEqual(ct, _ct)
                self.assertEqual(ss, _ss)
                
                # Affirmer les correspondances de décapsulation
                __ss = Kyber.dec(ct, sk)
                self.assertEqual(ss, __ss)
                
    def test_kyber512_known_answer(self):
        return self.generic_test_kyber_known_answer(Kyber512, "assets/PQCkemKAT_1632.rsp")
        
    def test_kyber768_known_answer(self):
        return self.generic_test_kyber_known_answer(Kyber768, "assets/PQCkemKAT_2400.rsp")
        
    def test_kyber1024_known_answer(self):
        return self.generic_test_kyber_known_answer(Kyber1024, "assets/PQCkemKAT_3168.rsp")

if __name__ == '__main__':
    unittest.main()