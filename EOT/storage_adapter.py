
"""
Session Behavior SDK - Monitoramento REAL de Comportamento
Captura interações reais do usuário em tempo real em toda a tela
"""

from dataclasses import dataclass, field
import pygame
import time
from datetime import datetime
import json
from typing import Dict, List, Optional, Any
from enum import Enum
import threading
from collections import defaultdict, deque
import logging
import pyautogui
from screeninfo import get_monitors
from pynput import mouse, keyboard
from pynput.mouse import Button, Controller as MouseController
from pynput.keyboard import Key, Listener as KeyboardListener
from device_info import DeviceEnvironmentSDK
from ip_location import session_id, IPLocationSDK
import cv2
import numpy as np
# from deepface import DeepFace # Removido DeepFace daqui, será usado apenas no servidor

# Configuração de logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class EventType(Enum):
    MOUSE_CLICK = "mouse_click"
    MOUSE_MOVE = "mouse_move"
    KEY_PRESS = "key_press"
    WINDOW_FOCUS = "window_focus"
    SCROLL = "scroll"
    DRAG = "drag"

@dataclass
class RealTimeEvent:
    event_id: str
    event_type: EventType
    timestamp: datetime
    position: Optional[Dict[str, int]] = None
    key: Optional[str] = None
    button: Optional[str] = None
    scroll_direction: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

# A classe FaceRecognitionMonitor foi removida ou simplificada, pois a lógica de reconhecimento
# será centralizada no servidor Flask (face_recognition_server.py)
# Se houver necessidade de alguma funcionalidade de monitoramento de face aqui, ela precisaria
# ser redesenhada para interagir com o servidor ou ser muito mais leve.

class RealTimeMonitor:
    def __init__(self):
        self.events: List[RealTimeEvent] = []
        self.is_monitoring = False
        self.monitor_thread = None
        self.mouse_listener = None
        self.keyboard_listener = None
        self.last_position = None
        self.click_count = 0
        self.keypress_count = 0
        self.start_time = None
        self.screen_width, self.screen_height = pyautogui.size()
        
        # Obter informações sobre todos os monitores
        self.monitors = []
        for m in get_monitors():
            self.monitors.append({
                "x": m.x,
                "y": m.y,
                "width": m.width,
                "height": m.height,
                "name": str(m.name)
            })
        
        logger.info(f"Tela detectada: {self.screen_width}x{self.screen_height}")
        logger.info(f"Monitores detectados: {len(self.monitors)}")
        
        # Configuração do pygame para visualização (opcional)
        pygame.init()
        self.screen = pygame.display.set_mode((300, 200))
        pygame.display.set_caption("EyeOfToga Monitor")
        # self.face_monitor = FaceRecognitionMonitor() # Removido, pois a lógica de face está no servidor

        
    def start_monitoring(self):
        """Inicia o monitoramento em tempo real"""
        if self.is_monitoring:
            logger.warning("Monitoramento já está ativo")
            return
        self.is_monitoring = True
        self.start_time = datetime.now()
        # Iniciar listeners para eventos globais
        self.mouse_listener = mouse.Listener(
            on_move=self._on_mouse_move,
            on_click=self._on_mouse_click,
            on_scroll=self._on_mouse_scroll
        )
        self.keyboard_listener = keyboard.Listener(
            on_press=self._on_key_press
        )
        self.mouse_listener.start()
        self.keyboard_listener.start()
        # self.face_monitor.start_recognition() # Removido
        logger.info("Monitoramento iniciado - Capturando suas interações em toda a tela...")

        
    def stop_monitoring(self):
        """Para o monitoramento"""
        self.is_monitoring = False
        if self.mouse_listener:
            self.mouse_listener.stop()
        if self.keyboard_listener:
            self.keyboard_listener.stop()
        # self.face_monitor.stop_recognition() # Removido
        logger.info("Monitoramento parado")

        
    def _on_mouse_move(self, x, y):
        """Callback para movimento do mouse em toda a tela"""
        if not self.is_monitoring:
            return
            
        current_pos = {"x": x, "y": y}
        
        # Registrar movimento se significativo
        if self.last_position and (
            abs(current_pos["x"] - self.last_position["x"]) > 2 or
            abs(current_pos["y"] - self.last_position["y"]) > 2
        ):
            self._record_mouse_move(current_pos)
        
        self.last_position = current_pos
    
    def _on_mouse_click(self, x, y, button, pressed):
        """Callback para clique do mouse em toda a tela"""
        if not self.is_monitoring or not pressed:
            return
            
        timestamp = datetime.now()
        
        button_name = str(button).split(".")[-1].lower()
        
        event_obj = RealTimeEvent(
            event_id=f"event_{len(self.events)}",
            event_type=EventType.MOUSE_CLICK,
            timestamp=timestamp,
            position={"x": x, "y": y},
            button=button_name,
            metadata={
                "screen_size": {"width": self.screen_width, "height": self.screen_height},
                "monitors": self.monitors
            }
        )
        
        self.events.append(event_obj)
        self.click_count += 1
        logger.info(f"Clique capturado: {button_name} em ({x}, {y}) - Total: {self.click_count}")
    
    def _on_mouse_scroll(self, x, y, dx, dy):
        """Callback para scroll do mouse em toda a tela"""
        if not self.is_monitoring:
            return
            
        timestamp = datetime.now()
        
        event_obj = RealTimeEvent(
            event_id=f"event_{len(self.events)}",
            event_type=EventType.SCROLL,
            timestamp=timestamp,
            position={"x": x, "y": y},
            scroll_direction="up" if dy > 0 else "down",
            metadata={
                "screen_size": {"width": self.screen_width, "height": self.screen_height},
                "monitors": self.monitors
            }
        )
        
        self.events.append(event_obj)
        logger.info(f"Scroll capturado: {"up" if dy > 0 else "down"} em ({x}, {y})")
    
    def _on_key_press(self, key):
        """Callback para tecla pressionada em toda a tela"""
        if not self.is_monitoring:
            return
            
        timestamp = datetime.now()
        
        try:
            # Tentar obter o caractere da tecla
            key_name = key.char
        except AttributeError:
            # Teclas especiais (shift, ctrl, etc)
            key_name = str(key).split(".")[-1].lower()
        
        event_obj = RealTimeEvent(
            event_id=f"event_{len(self.events)}",
            event_type=EventType.KEY_PRESS,
            timestamp=timestamp,
            key=key_name,
            metadata={
                "screen_size": {"width": self.screen_width, "height": self.screen_height}
            }
        )
        
        self.events.append(event_obj)
        self.keypress_count += 1
        logger.info(f"Tecla pressionada: {key_name} - Total: {self.keypress_count}")
    
    def _record_mouse_move(self, position):
        """Registra movimento do mouse"""
        timestamp = datetime.now()
        
        event_obj = RealTimeEvent(
            event_id=f"event_{len(self.events)}",
            event_type=EventType.MOUSE_MOVE,
            timestamp=timestamp,
            position=position,
            metadata={
                "screen_size": {"width": self.screen_width, "height": self.screen_height},
                "monitors": self.monitors
            }
        )
        self.events.append(event_obj)
            
    def get_click_and_key_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas detalhadas de cliques e teclas"""
        if not self.start_time:
            return {
                "total_clicks": self.click_count,
                "total_keypresses": self.keypress_count,
                "clicks_per_minute": 0.0,
                "keys_per_minute": 0.0,
                "session_duration_seconds": 0.0
            }
            
        duration_seconds = (datetime.now() - self.start_time).total_seconds()
        duration_minutes = duration_seconds / 60
        
        return {
            "total_clicks": self.click_count,
            "total_keypresses": self.keypress_count,
            "clicks_per_minute": self.click_count / duration_minutes if duration_minutes > 0 else 0.0,
            "keys_per_minute": self.keypress_count / duration_minutes if duration_minutes > 0 else 0.0,
            "session_duration_seconds": duration_seconds
        }
    
    def show_live_stats(self):
        """Mostra estatísticas em tempo real"""
        if not self.is_monitoring:
            print("❌ Monitoramento não está ativo")
            return
        stats = self.get_click_and_key_stats()
        print("\033[H\033[J")
        print("\n" + "="*50)
        print("📊 ESTATÍSTICAS EM TEMPO REAL")
        print("="*50)
        print(f"🖱️  Cliques totais: {stats["total_clicks"]}")
        print(f"⌨️  Teclas totais: {stats["total_keypresses"]}")
        print(f"⏱️  Duração: {stats["session_duration_seconds"]:.1f}s")
        print(f"📈 Cliques/min: {stats["clicks_per_minute"]:.1f}")
        print(f"📈 Teclas/min: {stats["keys_per_minute"]:.1f}")

        print("="*50)
    
    def get_session_summary(self) -> Dict[str, Any]:
        """Retorna resumo da sessão de monitoramento"""
        if not self.events or self.start_time is None:
            return {
                "status": "no_events",
                "session_start": None,
                "session_duration_seconds": 0,
                "total_events": 0,
                "event_counts": {},
                "events_per_minute": {},
                "total_clicks": 0,
                "total_keypresses": 0,
                "click_hotspots": [],
                "activity_level": "Nenhuma",
                "current_time": datetime.now().isoformat(),
                "screen_info": {
                    "width": self.screen_width,
                    "height": self.screen_height,
                    "monitors": self.monitors
                }
            }
            
        duration = (datetime.now() - self.start_time).total_seconds()
        
        # Contar eventos por tipo
        event_counts = defaultdict(int)
        for event in self.events:
            event_counts[event.event_type.value] += 1
            
        # Calcular taxa de eventos por minuto
        events_per_minute = {}
        for event_type, count in event_counts.items():
            events_per_minute[event_type] = (count / duration * 60) if duration > 0 else 0
        
        # Encontrar áreas mais clicadas
        click_positions = [
            event.position for event in self.events 
            if event.event_type == EventType.MOUSE_CLICK and event.position
        ]
        
        hotspots = []
        if click_positions:
            # Agrupar cliques por região (100x100 pixels para toda a tela)
            region_clicks = defaultdict(int)
            for pos in click_positions:
                region_x = (pos["x"] // 100) * 100
                region_y = (pos["y"] // 100) * 100
                region_clicks[f"{region_x},{region_y}"] += 1
                
            hotspots = sorted(
                [{"region": region, "clicks": count} 
                 for region, count in region_clicks.items()],
                key=lambda x: x["clicks"],
                reverse=True
            )[:5]  # Top 5 hotspots
        
        return {
            "session_start": self.start_time.isoformat(),
            "session_duration_seconds": round(duration, 2),
            "total_events": len(self.events),
            "event_counts": dict(event_counts),
            "events_per_minute": {k: round(v, 2) for k, v in events_per_minute.items()},
            "total_clicks": self.click_count,
            "total_keypresses": self.keypress_count,
            "click_hotspots": hotspots,
            "activity_level": self._calculate_activity_level(events_per_minute),
            "current_time": datetime.now().isoformat(),
            "screen_info": {
                "width": self.screen_width,
                "height": self.screen_height,
                "monitors": self.monitors
            }
        }
        
    def _calculate_activity_level(self, events_per_minute: Dict[str, float]) -> str:
        """Calcula nível de atividade baseado em eventos por minuto"""
        if not events_per_minute:
            return "Nenhuma"
            
        total_epm = sum(events_per_minute.values())
        
        if total_epm > 100:
            return "Muito Alta"
        elif total_epm > 50:
            return "Alta"
        elif total_epm > 10:
            return "Média"
        elif total_epm > 0:
            return "Baixa"
        else:
            return "Nenhuma"


# Exemplo de uso:
if __name__ == "__main__":
    monitor = RealTimeMonitor()
    
    # A lógica de reconhecimento facial foi movida para face_recognition_server.py
    # Para testar o monitoramento de eventos (mouse, teclado), descomente as linhas abaixo
    # monitor.start_monitoring()
    
    try:
        while True:
            time.sleep(1) 
            # monitor.show_live_stats() 
    except KeyboardInterrupt:
        print("Monitoramento interrompido pelo usuário.")
    finally:
        monitor.stop_monitoring()
        print("Resumo da sessão:")
        print(json.dumps(monitor.get_session_summary(), indent=4))

