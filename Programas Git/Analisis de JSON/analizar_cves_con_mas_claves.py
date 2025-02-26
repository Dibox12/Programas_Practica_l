import json
import os

def leer_cve(ruta_archivo):
    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)
        return cve_data
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{ruta_archivo}'")
        return None
    except json.JSONDecodeError:
        print(f"Error: El archivo '{ruta_archivo}' no es un JSON válido.")
        return None

def analizar_cves(ruta_base):
    palabras_clave = [
    # Conceptos generales de computación cuántica
    "quantum", "qubit", "superposition", "entanglement", "quantum algorithm", "quantum computer",
    "quantum software", "quantum cryptography", "quantum simulation", "quantum circuit",
    "quantum computing", "quantum information", "quantum mechanics", "quantum physics",
    "quantum error correction", "quantum decoherence", "quantum gate", "quantum state",
    "quantum system", "quantum processor", "quantum supremacy", "quantum advantage",

    # Algoritmos cuánticos
    "shor's algorithm", "grover's algorithm", "quantum fourier transform",
    "quantum phase estimation", "quantum walk", "quantum annealing",

    # Hardware cuántico
    "superconducting qubit", "trapped-ion qubit", "photonic qubit", "topological qubit",
    "quantum hardware", "quantum device", "quantum chip", "quantum control",

    # Software y desarrollo cuántico
    "quantum programming", "quantum development", "quantum sdk", "quantum framework",
    "quantum language", "quantum compiler", "quantum simulator", "quantum development kit",
    "qiskit", "cirq", "pennylane", "q#", "braket", "forest", "ocean", "strawberry fields",
    "tequila", "projectq",

    # Criptografía post-cuántica (criptografía resistente a la computación cuántica)
    "post-quantum cryptography", "quantum-resistant cryptography", "lattice-based cryptography",
    "code-based cryptography", "hash-based cryptography", "multivariate cryptography",
    "isogeny-based cryptography", "NIST PQC", "PQC standardization",

    # Seguridad cuántica
    "quantum security", "quantum vulnerability", "quantum attack", "quantum threat",
    "quantum risk", "quantum-safe", "quantum-secure",

    # Simulación cuántica (mencionar simuladores es importante, ya que podrían tener vulnerabilidades)
    "quantum simulator", "quantum simulation software", "quantum emulator",

    # Errores y ataques específicos (términos más técnicos)
    "quantum hacking", "quantum side-channel attack", "quantum fault tolerance",
    "quantum error detection", "quantum error mitigation",

    # Otros términos relacionados (empresas, instituciones, etc. -  investigar y agregar)
    "IBM Quantum", "Google Quantum AI", "Microsoft Quantum", "D-Wave", "Rigetti",
    "IonQ", "Honeywell", "AWS Braket", "Azure Quantum",

    #Palabras clave en español 
    "computación cuántica", "cúbit", "superposición", "entrelazamiento", "algoritmo cuántico",
    "computadora cuántica", "software cuántico", "criptografía cuántica", "simulación cuántica",
    "circuito cuántico", "información cuántica", "mecánica cuántica", "física cuántica",
    "corrección de errores cuánticos", "decoherencia cuántica", "puerta cuántica", "estado cuántico",
    "sistema cuántico", "procesador cuántico", "supremacía cuántica", "ventaja cuántica",
    "algoritmo de Shor", "algoritmo de Grover", "transformada cuántica de Fourier",
    "estimación de fase cuántica", "caminata cuántica", "temple cuántico",
    "cúbit superconductor", "cúbit de iones atrapados", "cúbit fotónico", "cúbit topológico",
    "hardware cuántico", "dispositivo cuántico", "chip cuántico", "control cuántico",
    "programación cuántica", "desarrollo cuántico", "SDK cuántico", "framework cuántico",
    "lenguaje cuántico", "compilador cuántico", "simulador cuántico", "kit de desarrollo cuántico",
    "criptografía post-cuántica", "criptografía resistente a la computación cuántica",
    "criptografía basada en retículos", "criptografía basada en código", "criptografía basada en hash",
    "criptografía multivariante", "criptografía basada en isogenias", "estandarización PQC",
    "seguridad cuántica", "vulnerabilidad cuántica", "ataque cuántico", "amenaza cuántica",
    "riesgo cuántico", "seguro cuánticamente", "simulador cuántico", "software de simulación cuántica",
    "emulador cuántico", "hacking cuántico", "ataque de canal lateral cuántico",
    "tolerancia a fallos cuánticos", "detección de errores cuánticos", "mitigación de errores cuánticos"
]
    cves_encontrados = []

    for subdir, dirs, files in os.walk(ruta_base):
        for file in files:
            if file.endswith(".json"):
                ruta_completa = os.path.join(subdir, file)
                cve_data = leer_cve(ruta_completa)

                if cve_data:
                    try:
                        # Ajuste para la nueva estructura del JSON
                        cve_id = cve_data['cveMetadata']['cveId']
                        descripcion = cve_data['containers']['cna']['descriptions'][0]['value']

                        print(f"CVE ID: {cve_id}")
                        print(f"Descripción: {descripcion}")

                        # Búsqueda de palabras clave
                        for palabra in palabras_clave:
                            if palabra in descripcion.lower():
                                print(f"  ** Palabra clave encontrada: {palabra}")
                                cves_encontrados.append(cve_id)
                                break

                        print("-" * 20)

                    except (KeyError, IndexError) as e:
                        print(f"Error al procesar el archivo {ruta_completa}: {e}")

    return cves_encontrados

if __name__ == "__main__":
    ruta_base_cve = "C:/Users/diego/Desktop/CVE/cvelistV5-main/cves/2024"  # Reemplaza con la ruta correcta a la carpeta de 2024

    cves_con_palabras_clave = analizar_cves(ruta_base_cve)

    if cves_con_palabras_clave:
        print("\nResumen:")
        print(f"Se encontraron {len(cves_con_palabras_clave)} CVEs con palabras clave relacionadas con computación cuántica:")
        for cve_id in cves_con_palabras_clave:
            print(f"- {cve_id}")
    else:
        print("\nNo se encontraron CVEs con palabras clave en la carpeta especificada.")