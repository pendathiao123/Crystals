from kyber import Kyber512, Kyber768, Kyber1024  # Importation des classes Kyber de différentes tailles
import cProfile  # Module pour le profilage de performances
from time import time  # Fonction pour mesurer le temps d'exécution

# Fonction pour profiler les performances de l'algorithme Kyber
def profile_kyber(Kyber):
    # Génération de la paire de clés publique et privée
    pk, sk = Kyber.keygen()
    # Chiffrement d'un message aléatoire
    c, key = Kyber.enc(pk)
    
    # Dictionnaires pour les variables globales et locales
    gvars = {}
    lvars = {"Kyber": Kyber, "c": c, "pk": pk, "sk": sk}
    
    # Profilage des opérations clés, de chiffrement et de déchiffrement
    cProfile.runctx("Kyber.keygen()", globals=gvars, locals=lvars, sort=1)
    cProfile.runctx("Kyber.enc(pk)", globals=gvars, locals=lvars, sort=1)
    cProfile.runctx("Kyber.dec(c, sk)", globals=gvars, locals=lvars, sort=1)

# Fonction pour mesurer les performances de l'algorithme Kyber
def benchmark_kyber(Kyber, name, count):
    # Affichage de l'en-tête
    print(f"-"*27)
    print(f"  {name} | ({count} appels)")
    print(f"-"*27)
    
    # Listes pour stocker les temps d'exécution
    keygen_times = []
    enc_times = []
    dec_times = []
    
    # Boucle pour effectuer les opérations plusieurs fois
    for _ in range(count):
        # Mesure du temps pour la génération de la paire de clés
        t0 = time()
        pk, sk = Kyber.keygen()
        keygen_times.append(time() - t0)
        
        # Mesure du temps pour le chiffrement
        t1 = time()
        c, key = Kyber.enc(pk)
        enc_times.append(time() - t1)
        
        # Mesure du temps pour le déchiffrement
        t2 = time()
        dec = Kyber.dec(c, sk)
        dec_times.append(time() - t2)
            
    # Affichage des temps d'exécution totaux pour chaque opération
    print(f"Keygen: {round(sum(keygen_times),3)}")
    print(f"Enc: {round(sum(enc_times), 3)}")
    print(f"Dec: {round(sum(dec_times),3)}")
    
    
if __name__ == '__main__':
    # Appel des fonctions pour profiler et mesurer les performances
    # profile_kyber(Kyber512)
    # profile_kyber(Kyber768)
    # profile_kyber(Kyber1024)
    
    # Nombre de répétitions pour le benchmarking
    count = 100
    # Benchmarking pour chaque taille de paramètre de Kyber
    benchmark_kyber(Kyber512, "Kyber512", count)
    benchmark_kyber(Kyber768, "Kyber768", count)    
    benchmark_kyber(Kyber1024, "Kyber1024", count)    
