import json
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import re
import nltk
from nltk.corpus import stopwords
from imblearn.over_sampling import SMOTE

# --- Funciones para cargar los datos ---

def cargar_cves_desde_json(nombre_archivo):
    try:
        with open(nombre_archivo, 'r', encoding='utf-8') as f:
            cves = json.load(f)
        return cves
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error al cargar los CVEs desde '{nombre_archivo}': {e}")
        return None

def cargar_issues_desde_json(nombre_archivo):
    try:
        with open(nombre_archivo, 'r', encoding='utf-8') as f:
            issues = json.load(f)
        return issues
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error al cargar los issues desde '{nombre_archivo}': {e}")
        return None

# --- Función para limpiar el texto ---

def limpiar_texto(texto):
    if isinstance(texto, str):  # Verificar si es una cadena
        texto = texto.lower()
        texto = re.sub(r'<.*?>', '', texto)  # Eliminar etiquetas HTML
        texto = re.sub(r'http\S+', '', texto)  # Eliminar URLs
        texto = re.sub(r'[^a-zA-Z\s]', '', texto)  # Eliminar caracteres que no sean letras ni espacios
        texto = re.sub(r'\s+', ' ', texto).strip()  # Eliminar espacios en blanco adicionales
        return texto
    else:
        return ""  # Retorna una cadena vacía si no es un string

# --- Función para eliminar stop words (opcional) ---

def eliminar_stopwords(texto, stop_words):
    palabras = texto.split()
    palabras_filtradas = [palabra for palabra in palabras if palabra not in stop_words]
    return " ".join(palabras_filtradas)

# --- Función para tokenizar (opcional) ---

def tokenizar(texto):
    return nltk.word_tokenize(texto)

# --- Función para etiquetar los datos (ejemplo) ---

def etiquetar_datos(cve_descripcion, issue_descripcion):
    palabras_clave_vulnerabilidad = ["vulnerability", "security", "exploit", "attack", "cve", "quantum"]

    if isinstance(issue_descripcion, str) and any(palabra in issue_descripcion.lower() for palabra in palabras_clave_vulnerabilidad):
        return 1  # Vulnerable

    if isinstance(cve_descripcion, str) and any(palabra in cve_descripcion.lower() for palabra in palabras_clave_vulnerabilidad):
        return 1  # Vulnerable

    return 0  # No vulnerable

# --- Programa principal ---
if __name__ == "__main__":
    # Cargar los datos de CVEs
    cves = cargar_cves_desde_json("cves_encontrados.json")
    if cves:
        df_cves = pd.DataFrame(cves)
    else:
        print("No se pudieron cargar los datos de CVEs. Saliendo.")
        exit()

    # Cargar los datos de issues
    issues = cargar_issues_desde_json("cp2k_cp2k_issues.json") # ¡Nombre de archivo actualizado!
    if issues:
        df_issues = pd.DataFrame(issues)
    else:
        print("No se pudieron cargar los datos de issues. Saliendo.")
        exit()

    # --- Combinar los datos de CVEs y de issues en un solo DataFrame ---

    df_cves['origen'] = 'cve'
    df_issues['origen'] = 'issue'

    # Unir los DataFrames
    df = pd.concat([df_cves, df_issues], ignore_index=True)

    # --- Limpieza de texto ---
    df['descripcion_limpia'] = df['description'].apply(limpiar_texto)

    # --- Eliminar stop words (opcional) ---
    stop_words = set(stopwords.words('english')) #Utilizar stop words en ingles
    df['descripcion_limpia'] = df['descripcion_limpia'].apply(lambda x: eliminar_stopwords(x, stop_words))

    # --- Tokenización (opcional) ---
    # df['descripcion_tokenizada'] = df['descripcion_limpia'].apply(tokenizar)

    # --- Etiquetado de datos ---
    df['etiqueta'] = df.apply(lambda row: etiquetar_datos(row.descripcion if row.origen == 'cve' else '', row.description if row.origen == 'issue' else ''), axis=1)

    # --- Vectorización ---
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), stop_words=list(stop_words))  # Ajusta los parámetros
    X = vectorizer.fit_transform(df['descripcion_limpia'])
    y = df['etiqueta']

    # --- Aplicar SMOTE para balancear las clases ---
    smote = SMOTE(random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X, y)

    # --- División de datos ---
    X_train, X_temp, y_train, y_temp = train_test_split(X_resampled, y_resampled, test_size=0.3, random_state=42, stratify=y_resampled)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp)

    # --- Implementación y evaluación de modelos ---
    # Ejemplo con Regresión Logística:
    model = LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced')
    model.fit(X_train, y_train)
    y_pred = model.predict(X_val)

    print("Resultados de la Regresión Logística:")
    print(classification_report(y_val, y_pred))
    print(confusion_matrix(y_val, y_pred))

    # --- Implementación y evaluación de modelos ---
    # Ejemplo con SVM:
    model = SVC(random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_val)

    print("Resultados de SVM:")
    print(classification_report(y_val, y_pred))
    print(confusion_matrix(y_val, y_pred))

    # --- Implementación y evaluación de modelos ---
    # Ejemplo con Naive Bayes:
    model = MultinomialNB()
    model.fit(X_train, y_train)
    y_pred = model.predict(X_val)

    print("Resultados de Naive Bayes:")
    print(classification_report(y_val, y_pred))
    print(confusion_matrix(y_val, y_pred))

    # --- Implementación y evaluación de modelos ---
    # Ejemplo con Random Forest:
    model = RandomForestClassifier(random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_val)

    print("Resultados de Random Forest:")
    print(classification_report(y_val, y_pred))
    print(confusion_matrix(y_val, y_pred))

    # --- Guardar el DataFrame procesado ---
    df.to_csv("datos_procesados.csv", index=False) #Cambiar el nombre si se desea