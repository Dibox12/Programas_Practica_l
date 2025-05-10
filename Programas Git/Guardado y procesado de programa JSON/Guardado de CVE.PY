import json
import os
import re

def leer_cve(ruta_archivo):
    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)
        return cve_data
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error al leer el archivo '{ruta_archivo}': {e}")
        return None

def extraer_info_relevante(cve_data):
    try:
        cve_id = cve_data['cveMetadata']['cveId']
        descripcion = cve_data['containers']['cna']['descriptions'][0]['value']
        fecha_publicacion = cve_data['cveMetadata']['datePublished']
        return {
            'cve_id': cve_id,
            'descripcion': descripcion,
            'fecha_publicacion': fecha_publicacion,
        }
    except (KeyError, IndexError) as e:
        print(f"No se han encontrado palabras claves en el CVE: {cve_data['cveMetadata']['cveId']}")
        return None

def procesar_cves(ruta_base, palabras_clave=None):
    """
    Procesa los archivos JSON de CVEs en la ruta especificada y sus subcarpetas.

    Args:
        ruta_base: La ruta base donde se encuentran las carpetas de años (ej. 'cvelistV5-main/cves').
        palabras_clave: Lista opcional de palabras clave para filtrar los CVEs.

    Returns:
        Una lista de diccionarios con la información relevante de los CVEs encontrados.
    """
    cves_encontrados = []

    for subdir, dirs, files in os.walk(ruta_base):
        for file in files:
            if file.endswith(".json"):
                ruta_completa = os.path.join(subdir, file)
                cve_data = leer_cve(ruta_completa)

                if cve_data:
                    info_relevante = extraer_info_relevante(cve_data)
                    if info_relevante:
                        if palabras_clave:
                          descripcion = info_relevante['descripcion'].lower()
                          if any(re.search(r'\b' + palabra + r'\b', descripcion) for palabra in palabras_clave):
                              print(f"  ** Palabra clave encontrada en {info_relevante['cve_id']}")
                              cves_encontrados.append(info_relevante)
                        else:
                            cves_encontrados.append(info_relevante)

    return cves_encontrados

def guardar_cves_en_json(cves, nombre_archivo):
    """
    Guarda la lista de CVEs en un archivo JSON.

    Args:
        cves: Lista de diccionarios con la información de los CVEs.
        nombre_archivo: Nombre del archivo JSON de salida.
    """
    with open(nombre_archivo, 'w', encoding='utf-8') as f:
        json.dump(cves, f, indent=4, ensure_ascii=False)

# --- Programa principal ---
if __name__ == "__main__":
    ruta_base_cve = "C:/Users/diego/Desktop/CVE/cvelistV5-main/cves/2024"  # Reemplaza con la ruta correcta a la carpeta 'cves'
    palabras_clave = [# Conceptos generales de computación cuántica
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
]
    
    cves_encontrados = procesar_cves(ruta_base_cve, palabras_clave)

    if cves_encontrados:
        nombre_archivo_salida = "cves_encontrados.json"
        guardar_cves_en_json(cves_encontrados, nombre_archivo_salida)
        print(f"Se han guardado {len(cves_encontrados)} CVEs en el archivo '{nombre_archivo_salida}'")
    else:
        print("No se encontraron CVEs que coincidan con los criterios de búsqueda.")
