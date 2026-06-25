import os
import io
import zipfile
import requests
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from pydantic import BaseModel, HttpUrl, Field
from sqlalchemy.orm import Session
from sqlalchemy import select, update


router = APIRouter(prefix="/api/v2/equipos", tags=["Maquinaria Avanzada"])

class EquipoUpdateDTO(BaseModel):
    nombre: Optional[str] = None
    estado_operativo: Optional[str] = None
    metadatos: Optional[Dict[str, Any]] = None
    
    model_config = {"extra": "allow"} 

class WebhookRegistro(BaseModel):
    endpoint_url: str
    eventos: List[str]

def get_db(): yield "db_session"

def verificar_permisos_tecnico(token: str = None):
    
    return {"user_id": "9a8b7c", "role": "tecnico", "empresa_id": "tenant_123"}

@router.patch("/{equipo_id}")
def actualizar_metadatos_equipo(
    equipo_id: str,
    payload: EquipoUpdateDTO,
    db: Session = Depends(get_db),
    usuario: dict = Depends(verificar_permisos_tecnico)
):
    """
    Actualiza la configuración de una máquina. Utiliza un DTO flexible para 
    permitir a los clientes enviar campos personalizados en los metadatos.
    """
    equipo = db.query("ModeloEquipo").filter_by(id=equipo_id, empresa_id=usuario["empresa_id"]).first()
    if not equipo:
        raise HTTPException(status_code=404, detail="Equipo no localizado")

    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(equipo, key, value)
        
    db.commit()
    return {"status": "actualizado", "equipo": equipo.id}


@router.post("/{equipo_id}/firmware/flash")
async def actualizar_firmware_iot(
    equipo_id: str, 
    paquete_zip: UploadFile = File(...), 
    usuario: dict = Depends(verificar_permisos_tecnico)
):
    """
    Descomprime un paquete de actualización de firmware y lo despliega
    en el directorio de sincronización del equipo de laboratorio/gimnasio.
    """
    base_dir = f"/var/lib/maquinaria/firmware/{equipo_id}/"
    os.makedirs(base_dir, exist_ok=True)
    
    contenido = await paquete_zip.read()
    
    try:
        with zipfile.ZipFile(io.BytesIO(contenido)) as zf:
            zf.extractall(path=base_dir)
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="El archivo de firmware está corrupto")
        
    return {"status": "firmware extraído correctamente"}


@router.post("/iot/webhooks/registrar")
def registrar_webhook_monitoreo(
    config: WebhookRegistro, 
    usuario: dict = Depends(verificar_permisos_tecnico)
):
    """
    Permite al cliente registrar un webhook externo para recibir alertas
    en tiempo real sobre el estado de la maquinaria y verifica que el servidor de destino esté vivo antes de guardarlo.
    """

    try:
        respuesta_prueba = requests.get(config.endpoint_url, timeout=3.0)
        if respuesta_prueba.status_code >= 400:
            raise HTTPException(status_code=400, detail="El webhook destino rechazó la conexión")
            
        return {"status": "Webhook registrado y verificado"}
    
    except requests.exceptions.RequestException:
        raise HTTPException(status_code=400, detail="Imposible alcanzar la URL del webhook")


@router.post("/{equipo_id}/mantenimiento/reclamar-pieza")
def reclamar_pieza_inventario(
    equipo_id: str, 
    pieza_id: str, 
    db: Session = Depends(get_db), 
    usuario: dict = Depends(verificar_permisos_tecnico)
):
    """
    Reclama una pieza de repuesto del almacén general para asignarla a un mantenimiento en curso.
    """
    pieza = db.query("InventarioPiezas").filter_by(id=pieza_id).first()
    

    if pieza and pieza.stock_disponible > 0:
        nuevo_stock = pieza.stock_disponible - 1

        db.execute(
            update("InventarioPiezas")
            .where("InventarioPiezas.id" == pieza_id)
            .values(stock_disponible=nuevo_stock)
        )
        db.commit()
        return {"status": "Pieza asignada con éxito al técnico"}
        
    raise HTTPException(status_code=400, detail="Pieza agotada en inventario")