#!/usr/bin/env python3
"""
Servidor Flask para Sistema de Reconhecimento Facial
Integra a interface web com o sistema de reconhecimento facial em tempo real
"""

from flask import Flask, render_template, request, jsonify, Response
import cv2
import numpy as np
import base64
import json
import os
from datetime import datetime
import threading
import time
from deepface import DeepFace
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

class FaceRecognitionServer:
    def __init__(self):
        self.known_faces = {}
        # Carregar o classificador Haar Cascade para detecção de faces
        self.face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        self.cap = None
        self.is_running = False
        self.current_frame = None
        self.recognition_results = []
        self.faces_directory = "known_faces"
        self.recognition_threshold = 1.0  # Threshold para distância euclidiana (ajustável)
        
        # Criar diretório para faces conhecidas se não existir
        if not os.path.exists(self.faces_directory):
            os.makedirs(self.faces_directory)
            
        # Carregar faces conhecidas existentes
        self.load_known_faces()
        
    def load_known_faces(self):
        """Carrega faces conhecidas do diretório"""
        logger.info("Carregando faces conhecidas...")
        try:
            for filename in os.listdir(self.faces_directory):
                if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                    # O nome da pessoa é o nome do arquivo sem extensão e sem o timestamp
                    name = os.path.splitext(filename)[0].rsplit('_', 1)[0] 
                    image_path = os.path.join(self.faces_directory, filename)
                    logger.info(f"Tentando adicionar face: {name} de {image_path}")
                    self._add_face_to_memory(name, image_path)
            logger.info(f"Total de {len(self.known_faces)} faces conhecidas carregadas.")
        except Exception as e:
            logger.error(f"Erro ao carregar faces conhecidas: {e}")

    def _add_face_to_memory(self, name, image_path):
        """Adiciona uma face (embedding) à memória do sistema"""
        try:
            # Extrair embedding usando DeepFace
            # enforce_detection=True garante que uma face seja detectada na imagem
            embedding_objs = DeepFace.represent(
                img_path=image_path, 
                model_name="VGG-Face", 
                enforce_detection=True
            )
            if embedding_objs:
                embedding = embedding_objs[0]["embedding"]
                self.known_faces[name] = {
                    'embedding': embedding,
                    'image_path': image_path,
                    'added_at': datetime.now().isoformat()
                }
                logger.info(f"Face de '{name}' adicionada com sucesso à memória.")
                return True
            else:
                logger.warning(f"Nenhuma face detectada em {image_path} para {name}. Não adicionada.")
                return False
        except Exception as e:
            logger.error(f"Erro ao extrair embedding para {name} de {image_path}: {e}")
            return False
    
    def add_known_face(self, name, image_path):
        """Adiciona uma face conhecida ao sistema (para uso externo) """
        # Este método é mais para compatibilidade, o _add_face_to_memory faz o trabalho real
        return self._add_face_to_memory(name, image_path)

    def save_uploaded_face(self, name, image_data):
        """Salva uma face enviada via upload e a adiciona ao sistema"""
        try:
            if image_data.startswith('data:image'):
                image_data = image_data.split(',')[1]
            
            image_bytes = base64.b64decode(image_data)
            
            # Salvar arquivo com timestamp para evitar sobrescrever
            filename = f"{name}_{int(time.time())}.jpg"
            filepath = os.path.join(self.faces_directory, filename)
            
            with open(filepath, 'wb') as f:
                f.write(image_bytes)
            
            logger.info(f"Imagem salva em: {filepath}")
            # Adicionar ao sistema de reconhecimento
            success = self._add_face_to_memory(name, filepath)
            return success, filepath
            
        except Exception as e:
            logger.error(f"Erro ao salvar face enviada: {e}")
            return False, None
    
    def recognize_face_in_frame(self, frame):
        """Detecta e reconhece faces em um frame da câmera"""
        results = []
        processed_frame = frame.copy() # Trabalhar em uma cópia para desenhar

        try:
            # Converter para escala de cinza para detecção com Haar Cascade
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = self.face_cascade.detectMultiScale(gray, 1.1, 4, minSize=(100, 100)) # Aumentar minSize para reduzir falsos positivos
            
            for (x, y, w, h) in faces:
                # Extrair região da face (ROI)
                face_roi = frame[y:y+h, x:x+w]
                recognized_name = "Unknown"
                
                if self.known_faces:
                    try:
                        # DeepFace.represent espera imagem em BGR (padrão do OpenCV)
                        face_embedding_objs = DeepFace.represent(
                            img_path=face_roi, 
                            model_name="VGG-Face", 
                            enforce_detection=False # Já detectamos com Haar Cascade
                        )
                        
                        if face_embedding_objs:
                            face_embedding = face_embedding_objs[0]["embedding"]
                            
                            min_distance = float('inf')
                            temp_recognized_name = "Unknown"
                            
                            for name, face_data in self.known_faces.items():
                                known_embedding = face_data['embedding']
                                
                                # Calcular distância euclidiana entre os embeddings
                                distance = np.linalg.norm(np.array(face_embedding) - np.array(known_embedding))
                                
                                if distance < min_distance:
                                    min_distance = distance
                                    temp_recognized_name = name
                            
                            if min_distance < self.recognition_threshold:
                                recognized_name = temp_recognized_name
                                logger.info(f"Face reconhecida: {recognized_name} com distância {min_distance:.2f}")
                            else:
                                logger.info(f"Face detectada, mas não reconhecida (distância {min_distance:.2f} > threshold {self.recognition_threshold})")
                        else:
                            logger.warning("DeepFace não conseguiu extrair embedding da face detectada pelo Haar Cascade.")
                            
                    except Exception as e:
                        logger.error(f"Erro durante o reconhecimento DeepFace para face em ({x},{y}): {e}")

                # Desenhar retângulo e nome no frame processado
                color = (0, 255, 0) if recognized_name != "Unknown" else (0, 0, 255) # Verde para conhecido, Vermelho para desconhecido
                cv2.rectangle(processed_frame, (x, y), (x+w, y+h), color, 2)
                cv2.putText(processed_frame, recognized_name, (x, y-10), 
                           cv2.FONT_HERSHEY_SIMPLEX, 0.9, color, 2, cv2.LINE_AA)
                
                results.append({
                    'name': recognized_name,
                    'bbox': [int(x), int(y), int(w), int(h)],
                    'distance': round(min_distance, 2) if recognized_name != "Unknown" else None
                })
            
            return results, processed_frame
            
        except Exception as e:
            logger.error(f"Erro geral no reconhecimento de faces no frame: {e}")
            return [], processed_frame
    
    def recognize_face(self, face_img):
        """Método auxiliar para reconhecimento de uma única face (não usado no loop principal) """
        # Este método é mantido para compatibilidade, mas a lógica principal está em recognize_face_in_frame
        if not self.known_faces:
            return "Unknown"
        
        try:
            face_embedding_objs = DeepFace.represent(
                img_path=face_img, 
                model_name="VGG-Face", 
                enforce_detection=False
            )
            
            if not face_embedding_objs:
                return "Unknown"
                
            face_embedding = face_embedding_objs[0]["embedding"]
            
            min_distance = float('inf')
            recognized_name = "Unknown"
            
            for name, face_data in self.known_faces.items():
                known_embedding = face_data['embedding']
                distance = np.linalg.norm(np.array(face_embedding) - np.array(known_embedding))
                
                if distance < min_distance:
                    min_distance = distance
                    recognized_name = name
            
            if min_distance < self.recognition_threshold:
                return recognized_name
            else:
                return "Unknown"
                
        except Exception as e:
            logger.error(f"Erro ao reconhecer face individual: {e}")
            return "Error"
    
    def start_camera(self):
        """Inicia captura da câmera"""
        try:
            self.cap = cv2.VideoCapture(0) # 0 para webcam padrão
            if not self.cap.isOpened():
                logger.error("Não foi possível abrir a câmera. Verifique se está em uso ou se há permissões.")
                return False
                
            self.is_running = True
            logger.info("Câmera iniciada com sucesso.")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao iniciar câmera: {e}")
            return False
    
    def stop_camera(self):
        """Para captura da câmera"""
        self.is_running = False
        if self.cap:
            self.cap.release()
        logger.info("Câmera parada.")
    
    def get_frame(self):
        """Obtém frame atual da câmera, processa e retorna"""
        if not self.cap or not self.is_running:
            return None
            
        ret, frame = self.cap.read()
        if not ret:
            logger.warning("Falha ao ler frame da câmera.")
            return None
            
        # Reconhecer faces no frame
        results, processed_frame = self.recognize_face_in_frame(frame)
        
        # Armazenar resultados para a API
        self.recognition_results = results
        self.current_frame = processed_frame
        
        return processed_frame
    
    def get_known_faces_list(self):
        """Retorna lista de faces conhecidas"""
        faces_list = []
        for name, data in self.known_faces.items():
            faces_list.append({
                'name': name,
                'added_at': data['added_at'],
                'image_path': data['image_path']
            })
        return faces_list

# Instância global do servidor
face_server = FaceRecognitionServer()

@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html')

@app.route('/api/start_camera', methods=['POST'])
def start_camera_api():
    """API para iniciar câmera"""
    logger.info("Requisição para iniciar câmera.")
    success = face_server.start_camera()
    return jsonify({'success': success})

@app.route('/api/stop_camera', methods=['POST'])
def stop_camera_api():
    """API para parar câmera"""
    logger.info("Requisição para parar câmera.")
    face_server.stop_camera()
    return jsonify({'success': True})

@app.route('/api/add_face', methods=['POST'])
def add_face_api():
    """API para adicionar nova face"""
    logger.info("Requisição para adicionar face.")
    try:
        data = request.get_json()
        name = data.get('name')
        image_data = data.get('image')
        
        if not name or not image_data:
            logger.warning("Nome ou imagem ausentes na requisição de adicionar face.")
            return jsonify({'success': False, 'error': 'Nome e imagem são obrigatórios'})
        
        success, filepath = face_server.save_uploaded_face(name, image_data)
        
        if success:
            return jsonify({
                'success': True, 
                'message': f'Face de {name} adicionada com sucesso',
                'filepath': filepath
            })
        else:
            return jsonify({'success': False, 'error': 'Erro ao processar imagem ou nenhuma face detectada'})
            
    except Exception as e:
        logger.error(f"Erro na API add_face: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get_faces', methods=['GET'])
def get_faces_api():
    """API para obter lista de faces conhecidas"""
    logger.info("Requisição para obter faces conhecidas.")
    faces = face_server.get_known_faces_list()
    return jsonify({'faces': faces})

@app.route('/api/recognition_results', methods=['GET'])
def get_recognition_results_api():
    """API para obter resultados do reconhecimento"""
    # logger.debug("Requisição para obter resultados de reconhecimento.") # Pode ser muito verboso
    return jsonify({'results': face_server.recognition_results})

def generate_frames():
    """Gerador de frames para streaming de vídeo"""
    while True:
        frame = face_server.get_frame()
        if frame is not None:            
            # Codificar frame como JPEG
            ret, buffer = cv2.imencode('.jpg', frame)
            if ret:
                frame_bytes = buffer.tobytes()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
        else:
            time.sleep(0.05) # Pequeno delay para evitar uso excessivo da CPU quando a câmera não está ativa

@app.route('/video_feed')
def video_feed():
    """Streaming de vídeo"""
    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# Criar template HTML se não existir
template_dir = 'templates'
if not os.path.exists(template_dir):
    os.makedirs(template_dir)

# Template HTML integrado
html_template = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Reconhecimento Facial - Servidor</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 20px;
        }
        .video-container {
            text-align: center;
            margin: 20px 0;
            position: relative;
        }
        #videoFeed {
            max-width: 100%;
            border: 2px solid #ddd;
            border-radius: 10px;
            display: block; /* Garante que a imagem ocupe o espaço */
            margin: 0 auto;
        }
        .controls {
            text-align: center;
            margin: 20px 0;
        }
        button {
            padding: 10px 20px;
            margin: 5px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s ease;
        }
        .btn-primary { background: #007bff; color: white; }
        .btn-primary:hover { background: #0056b3; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-danger:hover { background: #c82333; }
        .btn-success { background: #28a745; color: white; }
        .btn-success:hover { background: #218838; }
        .status {
            text-align: center;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            font-weight: bold;
        }
        .status.success { background: #d4edda; color: #155724; }
        .status.error { background: #f8d7da; color: #721c24; }
        .status.warning { background: #fff3cd; color: #856404; }
        .upload-section {
            margin: 30px 0;
            padding: 20px;
            border: 2px dashed #ddd;
            border-radius: 10px;
            text-align: center;
            background: #fdfdfd;
        }
        #imagePreview {
            max-width: 200px;
            max-height: 200px;
            margin: 10px auto;
            border-radius: 5px;
            display: block;
            object-fit: contain;
        }
        .faces-list {
            margin: 20px 0;
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 15px;
        }
        .face-item {
            flex: 0 0 calc(33% - 20px); /* 3 items per row, adjust as needed */
            max-width: calc(33% - 20px);
            margin: 10px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            text-align: center;
            background: #f9f9f9;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }
        @media (max-width: 768px) {
            .face-item {
                flex: 0 0 calc(50% - 20px);
                max-width: calc(50% - 20px);
            }
        }
        @media (max-width: 480px) {
            .face-item {
                flex: 0 0 calc(100% - 20px);
                max-width: calc(100% - 20px);
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Sistema de Reconhecimento Facial</h1>
        
        <div id="status" class="status warning">Sistema pronto</div>
        
        <div class="video-container">
            <img id="videoFeed" src="/video_feed" alt="Feed da câmera" style="display: none;">
        </div>
        
        <div class="controls">
            <button id="startBtn" class="btn-primary" onclick="startCamera()">Iniciar Câmera</button>
            <button id="stopBtn" class="btn-danger" onclick="stopCamera()" style="display: none;">Parar Câmera</button>
        </div>
        
        <div class="upload-section">
            <h3>Adicionar Nova Face</h3>
            <input type="file" id="imageInput" accept="image/*" onchange="previewImage()">
            <input type="text" id="nameInput" placeholder="Nome da pessoa" style="margin: 10px; padding: 5px;">
            <button class="btn-success" onclick="addFace()">Adicionar Face</button>
            <br>
            <img id="imagePreview" style="display: none;">
        </div>
        
        <div class="faces-list">
            <h3>Faces Cadastradas</h3>
            <div id="facesList"></div>
        </div>
    </div>

    <script>
        let isCameraRunning = false;
        let recognitionUpdateInterval;

        function updateStatus(message, type = '') {
            const status = document.getElementById('status');
            status.textContent = message;
            status.className = 'status ' + type;
        }

        async function startCamera() {
            try {
                updateStatus('Iniciando câmera...', 'warning');
                const response = await fetch('/api/start_camera', { method: 'POST' });
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('videoFeed').style.display = 'block';
                    document.getElementById('startBtn').style.display = 'none';
                    document.getElementById('stopBtn').style.display = 'inline-block';
                    updateStatus('Câmera ativa - Reconhecimento em tempo real', 'success');
                    isCameraRunning = true;
                    startRecognitionUpdates();
                } else {
                    updateStatus('Erro ao iniciar câmera. Verifique se a câmera está disponível e as permissões.', 'error');
                }
            } catch (error) {
                console.error('Erro de conexão ao iniciar câmera:', error);
                updateStatus('Erro de conexão ao iniciar câmera.', 'error');
            }
        }

        async function stopCamera() {
            try {
                const response = await fetch('/api/stop_camera', { method: 'POST' });
                
                document.getElementById('videoFeed').style.display = 'none';
                document.getElementById('startBtn').style.display = 'inline-block';
                document.getElementById('stopBtn').style.display = 'none';
                updateStatus('Câmera parada', 'warning');
                isCameraRunning = false;
                clearInterval(recognitionUpdateInterval);
            } catch (error) {
                console.error('Erro ao parar câmera:', error);
                updateStatus('Erro ao parar câmera.', 'error');
            }
        }

        function previewImage() {
            const input = document.getElementById('imageInput');
            const preview = document.getElementById('imagePreview');
            
            if (input.files && input.files[0]) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    preview.src = e.target.result;
                    preview.style.display = 'block';
                };
                reader.readAsDataURL(input.files[0]);
            } else {
                preview.style.display = 'none';
            }
        }

        async function addFace() {
            const nameInput = document.getElementById('nameInput');
            const imageInput = document.getElementById('imageInput');
            
            if (!nameInput.value || !imageInput.files[0]) {
                updateStatus('Por favor, forneça nome e selecione uma imagem.', 'error');
                return;
            }
            
            updateStatus('Adicionando face...', 'warning');
            const reader = new FileReader();
            reader.onload = async function(e) {
                try {
                    const response = await fetch('/api/add_face', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            name: nameInput.value,
                            image: e.target.result
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        updateStatus(data.message, 'success');
                        nameInput.value = '';
                        imageInput.value = '';
                        document.getElementById('imagePreview').style.display = 'none';
                        loadFaces();
                    } else {
                        updateStatus('Erro: ' + data.error, 'error');
                    }
                } catch (error) {
                    console.error('Erro de conexão ao adicionar face:', error);
                    updateStatus('Erro de conexão ao adicionar face.', 'error');
                }
            };
            reader.readAsDataURL(imageInput.files[0]);
        }

        async function loadFaces() {
            try {
                const response = await fetch('/api/get_faces');
                const data = await response.json();
                
                const facesList = document.getElementById('facesList');
                facesList.innerHTML = '';
                
                if (data.faces.length === 0) {
                    facesList.innerHTML = '<p>Nenhuma face cadastrada ainda.</p>';
                    return;
                }

                data.faces.forEach(face => {
                    const faceDiv = document.createElement('div');
                    faceDiv.className = 'face-item';
                    // Para exibir a imagem, precisaríamos de um endpoint para servir as imagens salvas
                    // Por enquanto, apenas o nome e data
                    faceDiv.innerHTML = `<strong>${face.name}</strong><br><small>Adicionado: ${new Date(face.added_at).toLocaleString()}</small>`;
                    facesList.appendChild(faceDiv);
                });
            } catch (error) {
                console.error('Erro ao carregar faces:', error);
                facesList.innerHTML = '<p style="color: red;">Erro ao carregar faces cadastradas.</p>';
            }
        }

        function startRecognitionUpdates() {
            if (recognitionUpdateInterval) {
                clearInterval(recognitionUpdateInterval);
            }
            recognitionUpdateInterval = setInterval(async () => {
                if (!isCameraRunning) return;
                
                try {
                    const response = await fetch('/api/recognition_results');
                    const data = await response.json();
                    
                    if (data.results && data.results.length > 0) {
                        const recognizedNames = data.results.filter(r => r.name !== "Unknown").map(r => r.name);
                        if (recognizedNames.length > 0) {
                            updateStatus(`Detectado: ${recognizedNames.join(', ')}`, 'success');
                        } else {
                            updateStatus('Face(s) detectada(s), mas não reconhecida(s).', 'warning');
                        }
                    } else {
                        updateStatus('Nenhuma face detectada.', 'warning');
                    }
                } catch (error) {
                    console.error('Erro ao obter resultados de reconhecimento:', error);
                    updateStatus('Erro ao obter resultados de reconhecimento.', 'error');
                }
            }, 1000); // Atualiza a cada segundo
        }

        // Carregar faces ao inicializar
        document.addEventListener('DOMContentLoaded', loadFaces);
    </script>
</body>
</html>
'''

# Salvar template
with open(os.path.join(template_dir, 'index.html'), 'w', encoding='utf-8') as f:
    f.write(html_template)

if __name__ == '__main__':
    print("🚀 Iniciando Servidor de Reconhecimento Facial...")
    print("📱 Acesse: http://localhost:5000")
    print("🔍 Sistema pronto para reconhecimento facial em tempo real!")
    
    try:
        # Usar debug=False e threaded=False para evitar problemas em alguns ambientes
        # Para desenvolvimento, debug=True pode ser útil, mas pode causar recarregamento duplo
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n⏹️ Servidor interrompido pelo usuário")
        face_server.stop_camera()
    except Exception as e:
        print(f"❌ Erro no servidor: {e}")
        face_server.stop_camera()

