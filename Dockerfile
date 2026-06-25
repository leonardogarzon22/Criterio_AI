# 1. Usar una imagen base oficial de Python ligera
FROM python:3.11-slim

# 2. Establecer el directorio de trabajo dentro del contenedor
WORKDIR /app

# 3. Copiar solo el archivo de dependencias primero
COPY requirements.txt .

# 4. Instalar las dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# 5. CREAR UN USUARIO SIN PRIVILEGIOS
RUN useradd -m appuser

# 6. Copiar el resto del código fuente
COPY . .

# 7. Asegurar que el usuario restringido sea el dueño de los archivos
RUN chown -R appuser:appuser /app

# 8. Cambiar al usuario sin privilegios a partir de este punto
USER appuser

# 9. Exponer el puerto que usará FastAPI
EXPOSE 8000

# 10. Comando para arrancar el servidor
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}