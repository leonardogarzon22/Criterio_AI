import os
import hashlib
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from supabase import create_client, Client
from google import genai
from google.genai import types
from dotenv import load_dotenv

# Carga variables de entorno
load_dotenv()

app = FastAPI(title="Chocolates Ancestrales - Gestión Total")

# --- CONFIGURACIÓN DE CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CONFIGURACIÓN DE SEGURIDAD ---
# Asegúrate de usar la SERVICE_ROLE_KEY en tu .env para que el backend tenga permisos totales
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
WOMPI_INTEGRITY_SECRET = os.getenv("WOMPI_INTEGRITY_SECRET")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Inicialización de clientes
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
client = genai.Client(api_key=GEMINI_API_KEY)

# --- MODELOS DE DATOS ---
class ChatRequest(BaseModel):
    pregunta: str

class SignatureRequest(BaseModel):
    reference: str
    amount_in_cents: int
    currency: str = "COP"

class Gasto(BaseModel):
    concepto: str
    monto: float
    categoria: Optional[str] = "General"

class PedidoItem(BaseModel):
    producto_id: int
    cantidad: int
    precio_unitario: float

class PedidoRequest(BaseModel):
    referencia: str
    email_cliente: str
    total: float
    items: List[PedidoItem]

# --- ENDPOINTS ---

@app.get("/")
async def root():
    return {"message": "Servidor Ancestral de Ventas y Contabilidad Activo"}

# 1. EL SOMMELIER (IA)
@app.post("/sommelier")
async def sommelier_ia(req: ChatRequest):
    try:
        productos_db = supabase.table("productos").select("*").execute()

        instrucciones_sistema = """
        Eres 'El Sommelier', un experto en cacao de origen de 'Chocolates Ancestrales'.
        TONO: Elegante, místico y cálido.
        REGLAS: Usa **negritas** para productos. Si preguntan salud, aclara que no eres médico.
        CATÁLOGO:
        """
        for p in productos_db.data:
            instrucciones_sistema += f"- **{p['nombre']}**: {p['perfil_sensorial']}. Maridaje: {p['maridaje_clave']}.\n"

        config = types.GenerateContentConfig(
            system_instruction=instrucciones_sistema,
            temperature=0.7,
            max_output_tokens=1000,
        )

        response = client.models.generate_content(
            model="gemini-2.0-flash",
            config=config,
            contents=req.pregunta
        )

        return {"respuesta": response.text if response.text else "Mi paladar está confundido..."}
    except Exception as e:
        print(f"Error IA: {str(e)}")
        return {"respuesta": "Mi cava de conocimientos está cerrada un momento."}

# 2. GESTIÓN DE VENTAS (PEDIDOS)
@app.post("/crear-pedido")
async def crear_pedido(req: PedidoRequest):
    """Registra el pedido y sus detalles antes de ir a Wompi"""
    try:
        # Insertar en tabla pedidos
        pedido_data = {
            "referencia_wompi": req.referencia,
            "email_cliente": req.email_cliente,
            "total_pagado": req.total,
            "estado": "pendiente",
            "fecha_creacion": datetime.now().isoformat()
        }
        res_pedido = supabase.table("pedidos").insert(pedido_data).execute()
        pedido_id = res_pedido.data[0]['id']

        # Insertar detalles (productos comprados)
        detalles = []
        for item in req.items:
            detalles.append({
                "pedido_id": pedido_id,
                "producto_id": item.producto_id,
                "cantidad": item.cantidad,
                "precio_unitario": item.precio_unitario
            })

        supabase.table("detalle_pedidos").insert(detalles).execute()

        return {"status": "ok", "pedido_id": pedido_id}
    except Exception as e:
        print(f"Error Creando Pedido: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# 3. SEGURIDAD WOMPI
@app.post("/generate-signature")
async def generate_signature(req: SignatureRequest):
    try:
        chain = f"{req.reference}{req.amount_in_cents}{req.currency}{WOMPI_INTEGRITY_SECRET}"
        signature = hashlib.sha256(chain.encode()).hexdigest()
        return {"signature": signature}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 4. WEBHOOK (CONFIRMACIÓN DE PAGO)
@app.post("/webhook-wompi")
async def webhook_wompi(data: dict):
    evento = data.get("event")
    transaccion = data.get("data", {}).get("transaction", {})

    if evento == "transaction.updated" and transaccion.get("status") == "APPROVED":
        ref = transaccion.get("reference")

        # Actualizar estado a pagado
        supabase.table("pedidos").update({"estado": "pagado"}).eq("referencia_wompi", ref).execute()

        # NOTA: Aquí puedes añadir un bucle para restar el stock en la tabla 'productos'
        # basándote en los IDs encontrados en 'detalle_pedidos'.

        print(f"Pago aprobado para referencia: {ref}")

    return {"status": "ok"}

# 5. LIBRO CONTABLE Y GESTIÓN DE GASTOS
@app.post("/registrar-gasto")
async def registrar_gasto(req: Gasto):
    try:
        data = {
            "concepto": req.concepto,
            "monto": req.monto,
            "categoria": req.categoria,
            "fecha": datetime.now().isoformat()
        }
        supabase.table("gastos").insert(data).execute()
        return {"status": "gasto_registrado"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/contabilidad-resumen")
async def resumen_contable():
    """Calcula Ingresos, Gastos y Utilidad Neta"""
    try:
        # Sumar ventas pagadas
        ventas = supabase.table("pedidos").select("total_pagado").eq("estado", "pagado").execute()
        total_ingresos = sum(v['total_pagado'] for v in ventas.data)

        # Sumar gastos
        gastos = supabase.table("gastos").select("monto").execute()
        total_egresos = sum(g['monto'] for g in gastos.data)

        return {
            "ingresos": total_ingresos,
            "egresos": total_egresos,
            "utilidad": total_ingresos - total_egresos,
            "conteo_ventas": len(ventas.data)
        }
    except Exception as e:
        return {"error": str(e)}
