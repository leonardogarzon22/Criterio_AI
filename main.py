import os
import json
import logging
import shutil
import tempfile
import subprocess
from typing import List, Optional
from fastapi import FastAPI, UploadFile, File, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Componentes de LangChain
from langchain_google_genai import ChatGoogleGenerativeAI

from langchain_core.prompts import ChatPromptTemplate

# Configuración de Logs profesional
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("SecAgentPro")

load_dotenv()

app = FastAPI(
    title="Criterio AppSec Engine — Multi-Language Edition",
    version="5.0.0",
    description="Motor profesional de auditoría de código con soporte políglota y análisis heurístico por IA."
)

# Configuración de CORS segura
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:5500,http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
if not GOOGLE_API_KEY:
    logger.critical("FALTA LA VARIABLE DE ENTORNO 'GOOGLE_API_KEY'")

llm = ChatGoogleGenerativeAI(
    model="gemini-3.1-flash-lite",
    temperature=0.0,  # Mantenemos 0.0 para que sea analítico y determinista
    google_api_key=GOOGLE_API_KEY
)


# MODELOS DE SALIDA ESTRUCTURADA (PYDANTIC v2)


class HallazgoSeguridad(BaseModel):
    endpoint: str = Field(description="Contexto, función o ruta afectada. Ej: '@app.get(/api/equipos)' o 'Función login()'")
    estado: str = Field(description="Debe ser estrictamente 'Seguro' o 'Inseguro'")
    linea_inicio: int = Field(description="Línea de código aproximada donde se detecta el problema (1-based)")
    categoria_owasp: str = Field(description="Categoría OWASP correspondiente. Ej: 'OWASP A01:2021-Broken Access Control'")
    descripcion: str = Field(description="Explicación técnica detallada del fallo detectado.")
    recomendacion: str = Field(description="Instrucciones precisas y código de ejemplo de cómo corregirlo.")

class ReporteAuditor(BaseModel):
    resumen: str = Field(description="Diagnóstico global ejecutivo de la arquitectura y calidad del archivo analizado.")
    hallazgos: List[HallazgoSeguridad] = Field(default=[], description="Lista de vulnerabilidades encontradas.")

class VectorAtaque(BaseModel):
    endpoint: str = Field(description="Punto de entrada explotable.")
    linea_objetivo: int = Field(description="Línea exacta donde impacta el ataque.")
    vector: str = Field(description="Explicación detallada de cómo un atacante explotaría esta falla.")
    payload_poc: str = Field(description="Código de prueba de concepto, payload HTTP, script XSS o cadena maliciosa para demostrar el fallo.")

class ReporteHacker(BaseModel):
    amenazas_detectadas: bool = Field(description="True si hay vectores viables de explotación, False si es seguro.")
    vectores: List[VectorAtaque] = Field(default=[], description="Vectores detallados de ataque.")

class ParcheCodigo(BaseModel):
    linea_remplazo: int = Field(description="Línea original donde se debe aplicar el parche.")
    codigo_corregido: str = Field(description="Bloque de código limpio, seguro y formateado listo para sustitución.")

class ReporteParcheador(BaseModel):
    parches: List[ParcheCodigo] = Field(default=[], description="Lista de soluciones en código.")
    
class VeredictoJuez(BaseModel):
    parche_exitoso: bool = Field(description="True si el parche soluciona la vulnerabilidad y NO rompe la sintaxis o lógica del código original. False si el parche es inválido o peligroso.")
    critica: str = Field(description="Si el parche falla, explica técnicamente por qué y qué debe cambiar el parcheador. Si es exitoso, escribe 'Aprobado'.")    



def extraer_contexto_codigo(codigo: str, linea_centro: int, radio: int = 10) -> str:
    """
    Extrae un bloque de código alrededor de una línea específica.
    Convierte el índice 1-based (del LLM) a 0-based (de Python).
    """
    lineas = codigo.split('\n')
    idx_centro = linea_centro - 1
    
    # Calcular los límites asegurando que no nos salgamos del archivo
    inicio = max(0, idx_centro - radio)
    fin = min(len(lineas), idx_centro + radio + 1)
    
    fragmento = []
    fragmento.append(f"// --- INICIO DE CONTEXTO (Línea {inicio + 1} a {fin}) ---")
    
    for i in range(inicio, fin):
        # Añadimos el número de línea real al inicio para que el modelo se oriente
        fragmento.append(f"{i + 1}: {lineas[i]}")
        
    fragmento.append(f"// --- FIN DE CONTEXTO ---")
    
    return "\n".join(fragmento)

def obtener_reglas_auditoria(extension: str) -> str:
    """Devuelve el modelo de amenazas OWASP exacto según el lenguaje de programación."""
    reglas_base = """
    Analiza el código línea por línea de manera implacable. Eres un auditor AppSec estricto.
    Si encuentras fallos lógicos o configuraciones peligrosas, márcalas como 'Inseguro'.
    Si el código sigue las mejores prácticas, no inventes vulnerabilidades falsas.
    """
    
    if extension in [".py"]:
        return reglas_base + """
        Foco de Inspección en PYTHON (FastAPI, Django, Flask):
        1. OWASP BOLA / IDOR: Consultas a la base de datos (.all(), .filter()) en arquitecturas multi-tenant que no validen la pertenencia del recurso con el ID del usuario autenticado (ej: usuario_actual.empresa_id).
        2. Autenticación Rota: Rutas operativas o críticas que no exijan token de sesión (falta de Depends).
        3. Path Traversal: Uso directo de 'file.filename' en un os.path.join sin sanitizar o generar UUIDs en el backend.
        4. Inyecciones: Consultas SQL crudas concatenadas en lugar de usar los métodos seguros del ORM.
        """
    elif extension in [".js", ".jsx", ".ts", ".tsx"]:
        return reglas_base + """
        Foco de Inspección en JAVASCRIPT / NODE.JS:
        1. XSS (Cross-Site Scripting): Uso inseguro de innerHTML, dangerouslySetInnerHTML o inserción directa de variables de usuarios en el DOM sin sanitización.
        2. Inyección de Comandos: Uso de 'eval()', 'exec()', o 'spawn()' pasando parámetros que el usuario controla.
        3. Fuga de Secretos: Hardcoding de API Keys, contraseñas de bases de datos o JWT tokens en el código del lado del cliente o scripts del servidor.
        4. Autenticación y JWT: Verificación débil de tokens, firmas sin verificar del lado del backend o almacenamiento inseguro en LocalStorage para datos financieros sensibles.
        """
    elif extension in [".html", ".php"]:
        return reglas_base + """
        Foco de Inspección en HTML / CSS / PHP embebido:
        1. Inyecciones SQL (PHP Clásico): Variables pasadas directamente en strings de consultas de MySQL sin usar Prepared Statements ($stmt->execute).
        2. XSS Embebido: Impresión directa en PHP usando 'echo $_GET[...]' o 'print' sin envolver en htmlspecialchars().
        3. CSRF (Cross-Site Request Forgery): Formularios POST que envían datos o ejecutan acciones pero no incluyen un token CSRF de validación.
        4. Inclusión de Archivos Insegura (LFI/RFI): Uso de 'include()', 'require()' pasándoles directamente parámetros de la URL sin una lista blanca rigurosa.
        """
    else:
        return reglas_base + "\nInspecciona debilidades generales de lógica de software, variables no definidas, falta de manejo de errores en bloques críticos y exposición de secretos."


#ENDPOINTS


@app.post('/analyze', status_code=status.HTTP_200_OK)
async def analyze_code(file: UploadFile = File(...)):
    nombre_archivo = file.filename
    _, ext = os.path.splitext(nombre_archivo.lower())
    
    
    EXTENSIONES_PERMITIDAS = [".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".php"]
    if ext not in EXTENSIONES_PERMITIDAS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Extensión {ext} no soportada. Permitidas: {', '.join(EXTENSIONES_PERMITIDAS)}"
        )

    
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as temp_file:
        shutil.copyfileobj(file.file, temp_file)
        ruta_temporal = temp_file.name

    try:
        
        with open(ruta_temporal, 'r', encoding='utf-8', errors='ignore') as f:
            codigo_fuente = f.read()
        
        LIMITE_CARACTERES = 16000
        if len(codigo_fuente) > LIMITE_CARACTERES:
            logger.warning(f"Archivo rechazado por tamaño: {len(codigo_fuente)} caracteres.")
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"El archivo es demasiado grande para el motor de IA. Límite: {LIMITE_CARACTERES} caracteres. Tu archivo: {len(codigo_fuente)}."
            ) 

        
        vulnerabilidades_sast = []
        if ext == ".py":
            try:
                result = subprocess.run(
                    ['bandit', '-r', ruta_temporal, '-f', 'json'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                if result.stdout:
                    try:
                        scan_results = json.loads(result.stdout)
                        vulnerabilidades_sast = scan_results.get('results', [])
                    except json.JSONDecodeError:
                        logger.warning("Bandit devolvió una salida no estructurada en JSON válido.")
            except Exception as e:
                logger.warning(f"No se pudo ejecutar Bandit en el sistema: {e}")

        sast_report_str = json.dumps(vulnerabilidades_sast, indent=2)
        instrucciones_lenguaje = obtener_reglas_auditoria(ext)

        
        # Agente 1: Auditor
        llm_auditor = llm.with_structured_output(ReporteAuditor)
        prompt_auditor = ChatPromptTemplate.from_messages([
            ("system", f"Eres un Ingeniero AppSec de Red Team. Evalúa minuciosamente las vulnerabilidades del código provisto.\n{instrucciones_lenguaje}"),
            ("user", "Analiza este código:\n{codigo}\n\nAlertas SAST:\n{sast}")
        ])
        cadena_auditor = prompt_auditor | llm_auditor
        
        logger.info(f"Iniciando fase de Auditoría para archivo: {nombre_archivo}")
        respuesta_auditor = await cadena_auditor.ainvoke({
            "sast": sast_report_str,
            "codigo": codigo_fuente
        })

        # Agente 2: Hacker Ofensivo
        llm_hacker = llm.with_structured_output(ReporteHacker)
        prompt_hacker = ChatPromptTemplate.from_messages([
            ("system", "Eres un analista de Red Team. Diseña vectores de ataque y payloads realistas basados estrictamente en el informe de auditoría provisto."),
            ("user", "Diseña los vectores de explotación basados en este reporte:\n{informe}")
        ])
        cadena_hacker = prompt_hacker | llm_hacker
        
        logger.info("Iniciando simulación ofensiva por IA...")
        respuesta_hacker = await cadena_hacker.ainvoke({
            "informe": respuesta_auditor.model_dump_json()
        })
        
        codigo_reducido = codigo_fuente # Fallback por defecto
        
        if respuesta_hacker.amenazas_detectadas and respuesta_hacker.vectores:
            fragmentos_afectados = []
            lineas_procesadas = set()
            
            for vector in respuesta_hacker.vectores:
                linea_obj = vector.linea_objetivo
                if linea_obj not in lineas_procesadas:
                    contexto = extraer_contexto_codigo(codigo_fuente, linea_obj, radio=10)
                    fragmentos_afectados.append(contexto)
                    lineas_procesadas.add(linea_obj)
            
            codigo_reducido = "\n\n".join(fragmentos_afectados)
            logger.info(f"Tokens ahorrados: Enviando solo {len(codigo_reducido.splitlines())} líneas al Parcheador en lugar de {len(codigo_fuente.splitlines())}")

        # Agente 3: Parcheador
        llm_parcheador = llm.with_structured_output(ReporteParcheador)
        prompt_parcheador = ChatPromptTemplate.from_messages([
            ("system", "Eres un Arquitecto de Software Seguro. Proporciona bloques de código limpios, robustos y completos, sin usar puntos suspensivos."),
            ("user", "Código Original (Contexto):\n{codigo}\n\nVectores:\n{vectores}\n\nFeedback previo:\n{criticas}")
        ])
        cadena_parcheador = prompt_parcheador | llm_parcheador
        
        # Agente 4: QA
        llm_juez = llm.with_structured_output(VeredictoJuez)
        prompt_juez = ChatPromptTemplate.from_messages([
            ("system", "Eres un Ingeniero Senior de QA. Evalúa si el parche propuesto soluciona el problema de seguridad de raíz sin romper la sintaxis o lógica del software."),
            ("user", "Código:\n{codigo_original}\n\nPropuesta:\n{parches}\n\n¿Es seguro y funcional?")
        ])
        cadena_juez = prompt_juez | llm_juez

        max_intentos = 3
        intento_actual = 0
        parche_aprobado = False
        historial_criticas = "Ninguna. Este es tu primer intento."
        respuesta_parcheador = None
        
        if not respuesta_hacker.amenazas_detectadas:
             respuesta_parcheador = ReporteParcheador(parches=[])
             parche_aprobado = True
             logger.info("No se detectaron amenazas. Omitiendo la fase de parcheo.")
        else:
             logger.info("Iniciando generación automatizada de parches con validación de QA por IA...")

        while intento_actual < max_intentos and not parche_aprobado:
            intento_actual += 1
            logger.info(f"--- Evaluando Parche (Intento {intento_actual}/{max_intentos}) ---")
            
            respuesta_parcheador = await cadena_parcheador.ainvoke({
                "codigo": codigo_reducido,
                "vectores": respuesta_hacker.model_dump_json(),
                "criticas": historial_criticas
            })

            logger.info("El Agente Juez está analizando la integridad del código parcheado...")
            veredicto = await cadena_juez.ainvoke({
                "codigo_original": codigo_reducido,
                "parches": respuesta_parcheador.model_dump_json()
            })

            if veredicto.parche_exitoso:
                parche_aprobado = True
                logger.info(f"✅ Veredicto: Parche Aprobado en el intento {intento_actual}.")
            else:
                historial_criticas = veredicto.critica
                logger.warning(f"❌ Veredicto: Parche Rechazado. Razón: {historial_criticas}")

        if not parche_aprobado:
            logger.error("Se agotaron los intentos. El parcheador no logró una solución válida.")
            respuesta_parcheador = ReporteParcheador(parches=[])

        return {
            'status': 'success',
            'archivo': nombre_archivo,
            'hallazgos_sast_puros': len(vulnerabilidades_sast),
            'codigo_original': codigo_fuente,
            'auditoria': respuesta_auditor,
            'hacking': respuesta_hacker,
            'parches': respuesta_parcheador
        }

    except Exception as e:
        logger.error(f"Fallo catastrófico durante el análisis: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno del motor de análisis: {str(e)}"
        )
        
    finally:
        # Limpieza obligatoria del archivo temporal en el sistema de archivos
        if os.path.exists(ruta_temporal):
            os.remove(ruta_temporal)
            logger.info("Limpieza de archivos temporales completada de forma segura.")