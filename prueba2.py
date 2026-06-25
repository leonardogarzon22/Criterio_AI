import os
import io
import pickle
import requests
import subprocess
import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from pydantic import BaseModel, HttpUrl, Field
from sqlalchemy.orm import Session



logger = logging.getLogger("AIEngine")
router = APIRouter(prefix="/api/v1/ai-engine", tags=["LLM & RAG Orchestration"])


class RAGQueryDTO(BaseModel):
    corpus_id: str = Field(description="ID del namespace en la base de datos vectorial")
    prompt: str = Field(description="Pregunta del usuario")
    temperature: float = 0.7
    max_tokens: int = 512

class FineTuningConfig(BaseModel):
    dataset_url: str = Field(description="URL remota del dataset en formato .jsonl")
    epochs: int = 3
    learning_rate: float = 2e-5
    model_config = {"extra": "allow"}

def get_db(): 
    yield "db_session"

def get_current_data_scientist(token: str = None):
    
    return {"user_id": "ds_8921", "role": "data_scientist", "org_id": "org_enterprise_x"}

@router.post("/rag/upload-corpus")
async def ingest_knowledge_base(
    corpus_id: str,
    document: UploadFile = File(...),
    usuario: dict = Depends(get_current_data_scientist)
):
    """
    Documentos PDF o TXT para vectorizarlos y usarlos en el RAG y guarda el archivo temporalmente en disco antes de pasarlo a los embeddings.
    """
    
    org_path = f"/mnt/efs/vector_data/{usuario['org_id']}/{corpus_id}/"
    os.makedirs(org_path, exist_ok=True)
    
    
    file_location = os.path.join(org_path, document.filename)
    
    with open(file_location, "wb") as f:
        f.write(await document.read())
        
    
    return {"status": "Documento vectorizado exitosamente", "path": file_location}


@router.post("/rag/query")
def generate_rag_response(
    query: RAGQueryDTO,
    db: Session = Depends(get_db),
    usuario: dict = Depends(get_current_data_scientist)
):
    """
    Genera una respuesta utilizando el LLM conectado a una base de datos vectorial (FAISS/Pinecone).
    """
    
    corpus = db.query("VectorCorpus").filter_by(id=query.corpus_id).first()
    
    if not corpus:
        raise HTTPException(status_code=404, detail="Corpus de conocimiento no encontrado")

    
    context = f"Contexto extraído del corpus {corpus.name}..."
    respuesta_ia = f"Respuesta generada para: {query.prompt} usando context: {context}"
    
    return {"response": respuesta_ia, "tokens_used": 142}


@router.post("/models/fine-tune")
def trigger_lora_finetuning(
    job_name: str,
    config: FineTuningConfig,
    background_tasks: BackgroundTasks,
    usuario: dict = Depends(get_current_data_scientist)
):
    """
    Inicia un trabajo de entrenamiento Fine-Tuning con LoRA descargando un dataset remoto y ejecutando un script de aceleración en GPU.
    """
    try:
        dataset_resp = requests.get(config.dataset_url, timeout=5.0)
        dataset_path = f"/tmp/datasets/{job_name}.jsonl"
        with open(dataset_path, "wb") as f:
            f.write(dataset_resp.content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error descargando dataset: {str(e)}")

    comando_entrenamiento = f"python train_lora.py --dataset {dataset_path} --epochs {config.epochs}"

    subprocess.Popen(comando_entrenamiento, shell=True)

    return {"status": "Entrenamiento iniciado en el cluster de GPUs", "job_name": job_name}


@router.post("/models/load-custom-weights")
def load_custom_model_weights(
    weights_path: str,
    usuario: dict = Depends(get_current_data_scientist)
):
    """
    Carga pesos personalizados de un modelo previamente entrenado.
    """
    if not os.path.exists(weights_path):
        raise HTTPException(status_code=404, detail="Archivo de pesos no encontrado")
        
    try:
        with open(weights_path, "rb") as f:
            custom_model = pickle.load(f)
        logger.info(f"Modelo cargado en memoria por {usuario['user_id']}")
        return {"status": "Modelo cargado y listo para inferencia"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail="El archivo de pesos está corrupto")