import platform
import socket
import psutil
import requests
import json
import time
import subprocess
import uuid
import locale
import datetime
from typing import Dict, Any, Optional, Tuple
import netifaces
import re

class DeviceEnvironmentSDK:
    """
    SDK para coleta de dados do dispositivo e ambiente
    Parte do TCC de Cyber Segurança - Módulo de Coleta de Dados
    
    Esta classe é responsável por identificar e coletar informações sobre:
    - Tipo de dispositivo (servidor físico, VM, container, desktop, IoT, mobile)
    - Recursos de hardware (memória RAM)
    - Informações do sistema (hostname, idioma, localização)
    - Dados de rede (IP, provedor, tipo de conexão, status)
    - Informações do navegador (para versão web do SDK)
    """

    def __init__(self):
        """Inicializa o SDK com configurações básicas"""
        self.session = requests.Session()
        self.cache_data = {}  # Para armazenar dados em cache entre chamadas
        
    def detect_device_type(self) -> str:
        """
        Detecta o tipo de dispositivo baseado em características do sistema
        Retorna: servidor, vm, container, desktop, iot, mobile, etc.
        
        Esta função analisa várias características do sistema para determinar
        o tipo de dispositivo em que o código está sendo executado.
        """
        try:
            system = platform.system().lower()
            machine = platform.machine().lower()
            
            # Verifica se é container (Docker, Kubernetes)
            if self._is_container():
                return "container"
            
            # Verifica se é VM através de várias técnicas de detecção
            if self._is_virtual_machine():
                return "desktop"
            
            # Verifica se é servidor (normalmente sem interface gráfica ou headless)
            if system == "linux" or system == "windows" and not self._has_gui():
                return "servidor físico"
            
            # Dispositivos móveis (Android/iOS)
            if system == "android" or system == "ios":
                return "mobile"
            
            # IoT devices (ARM architecture comum em IoT)
            if "arm" in machine or "aarch" in machine:
                return "iot"
            
            if system == "linux" or system == "windows" or system == "macOS" and self._has_gui():
            # Desktop por padrão (Windows, macOS, Linux com interface gráfica)
               return "desktop"
            
        except Exception as e:
            return f"desktop (erro na detecção: {str(e)})"
    
    def _is_container(self) -> bool:
        """Verifica se está rodando em container (Docker, Kubernetes, etc.)"""
        try:
            # Verifica arquivos comuns em containers
            container_indicators = [
                '/.dockerenv',
                '/.dockerinit',
                '/proc/1/cgroup'
            ]
            
            for indicator in container_indicators:
                try:
                    with open(indicator, 'r') as f:
                        content = f.read()
                        if 'docker' in content.lower() or 'kubepods' in content.lower():
                            return True
                except:
                    continue
            
            return False
        except:
            return False
    
    def _is_virtual_machine(self) -> bool:
        """Verifica se está rodando em máquina virtual através de múltiplas técnicas"""
        try:
            # Verifica através de informações do sistema
            system_info = platform.uname()
            
            # Hipervisores comuns em system info
            hypervisors = ['vmware', 'virtualbox', 'kvm', 'xen', 'hyper-v', 'qemu']
            
            for hv in hypervisors:
                if hv in system_info.version.lower() or hv in system_info.release.lower():
                    return False
            
            # Verifica através de dispositivos virtuais (Linux)
            if platform.system().lower() == 'linux':
                try:
                    with open('/sys/class/dmi/id/product_name', 'r') as f:
                        product_name = f.read().lower()
                        if any(hv in product_name for hv in hypervisors):
                            return False
                except:
                    pass
            
            # Verifica através de processos relacionados a virtualização
            for proc in psutil.process_iter(['name']):
                if any(hv in proc.info['name'].lower() for hv in hypervisors):
                    return True
            
            return False
        except:
            return False

    def new_method(self):
        pass
    
    def _has_gui(self) -> bool:
        """Verifica se o sistema possui interface gráfica"""
        try:
            if platform.system().lower() == 'windows':
                return True
            
            # Para Linux/Unix, verifica se há display configurado
            import os
            return 'DISPLAY' in os.environ and os.environ['DISPLAY'] != ''
        except:
            return False
    
    def get_memory_info(self) -> Dict[str, Any]:
        """
        Obtém informações detalhadas de memória RAM
        Retorna: total, disponível, percentual de uso em GB e porcentagem
        
        Esta função usa a biblioteca psutil para acessar estatísticas
        detalhadas sobre o uso de memória do sistema.
        """
        try:
            memory = psutil.virtual_memory()
            return {
                'total_memory_gb': round(memory.total / (1024**3), 2),
                'available_memory_gb': round(memory.available / (1024**3), 2),
                'memory_usage_percent': memory.percent,
                'used_memory_gb': round(memory.used / (1024**3), 2),
                'free_memory_gb': round(memory.free / (1024**3), 2)
            }
        except Exception as e:
            return {'error': f'Erro ao obter informações de memória: {str(e)}'}
    
    def get_host_info(self) -> Dict[str, Any]:
        """
        Obtém informações detalhadas do host/sistema
        Retorna: nome do host, sistema operacional, arquitetura, etc.
        
        Coleta identificadores únicos e informações de sistema que
        ajudam a identificar unicamente o dispositivo.
        """
        try:
            return {
                'hostname': socket.gethostname(),
                'operating_system': platform.system(),
                'os_version': platform.version(),
                'architecture': platform.machine(),
                'platform': platform.platform(),
                'processor': platform.processor(),
                'unique_id': str(uuid.getnode())  # Identificador único do dispositivo
            }
        except Exception as e:
            return {'error': f'Erro ao obter informações do host: {str(e)}'}
    
    def get_language_location(self) -> Dict[str, Any]:
        """
        Obtém informações de idioma, localização e configurações regionais
        Retorna: idioma, codificação, timezone, configuração regional
        
        Essas informações são importantes para personalização e compliance
        com regulamentações regionais de privacidade de dados.
        """
        try:
            # Idioma e localização
            lang, encoding = locale.getdefaultlocale()
            
            # Timezone
            timezone = datetime.datetime.now(datetime.timezone.utc).astimezone().tzname()
            
            return {
                'language': lang,
                'encoding': encoding,
                'timezone': timezone,
                'locale': locale.setlocale(locale.LC_ALL),
                'current_time': datetime.datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': f'Erro ao obter informações de localização: {str(e)}'}
    
    def get_network_info(self) -> Dict[str, Any]:
        """
        Obtém informações detalhadas de rede
        Retorna: interfaces, IPs, gateway, DNS, endereço MAC
        
        Coleta informações completas sobre todas as interfaces de rede
        disponíveis no dispositivo, incluindo IPv4 e IPv6.
        """
        try:
            interfaces = {}
            default_gateway = netifaces.gateways().get('default', {})

            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                interfaces[interface] = {}
                if netifaces.AF_INET in addrs:
                    ipv4_info = addrs[netifaces.AF_INET][0]
                    interfaces[interface]['ipv4'] = ipv4_info.get('addr')
                    interfaces[interface]['netmask'] = ipv4_info.get('netmask')
                    interfaces[interface]['broadcast'] = ipv4_info.get('broadcast')
                if netifaces.AF_INET6 in addrs:
                    ipv6_info = addrs[netifaces.AF_INET6][0]
                    interfaces[interface]['ipv6'] = ipv6_info.get('addr')

            # Obtém IP local principal
            try:
                hostname = socket.gethostname()
                local_ipv4 = socket.gethostbyname(hostname)
            except Exception:
                local_ipv4 = None

            # Coleta todos os IPs do host
            ip_list = []
            try:
                for info in socket.getaddrinfo(hostname, None):
                    ip = info[4][0]
                    if ip not in ip_list:
                        ip_list.append(ip)
            except Exception:
                pass

            # Obtém IP público
            public_ip = None
            try:
                response = self.session.get('https://api.ipify.org?format=json', timeout=5)
                public_ip = response.json().get('ip')
            except Exception:
                public_ip = None

            return {
                'local_ipv4': local_ipv4,
                'ip_list': ip_list,
                'public_ip': public_ip,
                'interfaces': interfaces,
                'default_gateway': default_gateway,
                'mac_address': self._get_mac_address(),
                'dns_servers': self._get_dns_servers(),
                'connection_type': self.get_connection_type()
            }

        except Exception as e:
            return {'error': f'Erro ao obter informações de rede: {str(e)}'}
    
    def _get_mac_address(self) -> str:
        """Obtém endereço MAC da interface principal"""
        try:
            return ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        except:
            return "unknown"
    
    def _get_dns_servers(self) -> list:
        """Obtém servidores DNS configurados no sistema"""
        try:
            if platform.system() == 'Windows':
                output = subprocess.check_output(['ipconfig', '/all']).decode()
                dns_servers = re.findall(r'DNS Servers[^:]*:\s*([\d.]+)', output)
            else:
                with open('/etc/resolv.conf', 'r') as f:
                    content = f.read()
                    dns_servers = re.findall(r'nameserver\s+([\d.]+)', content)
            
            return dns_servers
        except:
            return []
    
    def get_connection_type(self) -> str:
        """
        Detecta o tipo de conexão de rede ativa
        Retorna: Ethernet, Wi-Fi, LTE, 5G, etc.
        
        Usa diferentes métodos dependendo do sistema operacional
        para determinar o tipo de conexão de rede.
        """
        try:
            if platform.system() == 'Windows':
                return self._detect_connection_type_windows()
            elif platform.system() == 'Linux':
                return self._detect_connection_type_linux()
            elif platform.system() == 'Darwin':
                return self._detect_connection_type_mac()
            else:
                return "unknown"
        except Exception as e:
            return f"unknown (erro: {str(e)})"
    
    def _detect_connection_type_windows(self) -> str:
        """Detecta tipo de conexão no Windows usando comandos nativos"""
        try:
            # Verifica se há interfaces Wi-Fi ativas
            output = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces']).decode()
            if 'SSID' in output and 'BSSID' in output:
                return "wi-fi"
            
            # Verifica conexões móveis (apenas para Windows 10+)
            try:
                output = subprocess.check_output(['netsh', 'mbn', 'show', 'interfaces']).decode()
                if 'Mobile broadband' in output:
                    return "LTE/5G"
            except:
                pass
                
            return "ethernet"
        except:
            return "ethernet"
    
    def _detect_connection_type_linux(self) -> str:
        """Detecta tipo de conexão no Linux analisando interfaces de rede"""
        try:
            # Verifica interfaces wireless
            output = subprocess.check_output(['iwconfig']).decode()
            if 'ESSID' in output:
                return "wi-fi"
            
            # Verifica conexões móveis
            output = subprocess.check_output(['mmcli', '-L']).decode()
            if 'Modem' in output:
                return "LTE/5G"
                
            return "ethernet"
        except:
            return "ethernet"
    
    def _detect_connection_type_mac(self) -> str:
        """Detecta tipo de conexão no macOS usando comandos nativos"""
        try:
            output = subprocess.check_output(['networksetup', '-listallhardwareports']).decode()
            if 'Wi-Fi' in output or 'AirPort' in output:
                return "wi-fi"
            if 'Cellular' in output or 'WWAN' in output:
                return "LTE/5G"
            return "ethernet"
        except:
            return "ethernet"
    
    def get_connection_status(self) -> Dict[str, Any]:
        """
        Testa status da conexão e mede métricas de qualidade
        Retorna: online, latência, jitter, perda de pacotes
        
        Realiza testes de conectividade para servidores confiáveis
        e calcula métricas de qualidade de rede importantes para
        aplicações sensíveis a latência.
        """
        try:
            test_servers = [
                '8.8.8.8',  # Google DNS
                '1.1.1.1',  # Cloudflare DNS
                '208.67.222.222'  # OpenDNS
            ]
            
            latencies = []
            for server in test_servers:
                try:
                    start_time = time.time()
                    socket.create_connection((server, 53), timeout=5).close()
                    latency = (time.time() - start_time) * 1000  # ms
                    latencies.append(latency)
                except:
                    continue
            
            if not latencies:
                return {'online': False, 'latency': None, 'jitter': None}
            
            avg_latency = sum(latencies) / len(latencies)
            max_latency = max(latencies)
            
            # Calcula jitter (variação de latência)
            jitter = sum(abs(latencies[i] - latencies[i-1]) for i in range(1, len(latencies))) / (len(latencies) - 1) if len(latencies) > 1 else 0
            
            return {
                'online': True,
                'average_latency_ms': round(avg_latency, 2),
                'max_latency_ms': round(max_latency, 2),
                'jitter_ms': round(jitter, 2),
                'packet_loss': False,
                'tested_servers': test_servers
            }
            
        except Exception as e:
            return {'online': False, 'error': str(e)}
    
    def get_isp_info(self) -> Dict[str, Any]:
        """
        Obtém informações do provedor de internet e localização geográfica
        Retorna: ASN, ISP, país, cidade, coordenadas
        
        Utiliza API pública para obter informações baseadas no IP público
        do dispositivo. Essas informações são úteis para geolocalização
        e análise de tráfego de rede.
        """
        try:
            # Usa serviço externo para obter informações do IP
            response = self.session.get('https://ipapi.co/json/', timeout=10)
            data = response.json()
            
            return {
                'ip': data.get('ip'),
                'asn': data.get('asn'),
                'asn_organization': data.get('org'),
                'isp': data.get('org'),
                'country': data.get('country_name'),
                'country_code': data.get('country_code'),
                'region': data.get('region'),
                'city': data.get('city'),
                'postal_code': data.get('postal'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude')
            }
        except Exception as e:
            return {'error': f'Erro ao obter informações do ISP: {str(e)}'}
    
    def get_browser_info(self) -> Dict[str, Any]:
        """
        Obtém informações do navegador (para SDK web)
        Retorna: user agent, nome, versão, plataforma, idioma
        
        NOTA: Esta é uma implementação simulada para ambiente Python.
        Em ambiente web real, isso seria implementado em JavaScript
        para acessar as propriedades do navegador.
        """
        try:
            # Em ambiente web real, estas informações seriam obtidas via JavaScript
            # com: navigator.userAgent, navigator.appVersion, navigator.platform, etc.
            return {
                'user_agent': 'Simulado - Em ambiente web use navigator.userAgent',
                'browser_name': 'Simulado',
                'browser_version': 'Simulado',
                'platform': 'Simulado',
                'language': 'Simulado',
                'cookie_enabled': True,
                'do_not_track': None
            }
        except:
            return {'error': 'Informações do navegador disponíveis apenas em ambiente web'}
    
    def collect_all_data(self) -> Dict[str, Any]:
        """
        Coleta todos os dados do dispositivo e ambiente de forma abrangente
        Retorna: dicionário completo com todas as informações categorizadas
        
        Esta função principal orquestra a coleta de todos os dados e organiza
        em uma estrutura padronizada para fácil consumo.
        """
        timestamp = datetime.datetime.now().isoformat()
        
        data = {
            'timestamp': timestamp,
            'device_type': self.detect_device_type(),
            'memory_info': self.get_memory_info(),
            'host_info': self.get_host_info(),
            'language_location': self.get_language_location(),
            'network_info': self.get_network_info(),
            'connection_type': self.get_connection_type(),
            'connection_status': self.get_connection_status(),
            'isp_info': self.get_isp_info(),
            'browser_info': self.get_browser_info(),
            'sdk_version': '1.0.0',
            'collection_id': str(uuid.uuid4())  # ID único para esta coleta
        }
        
        self.cache_data = data  # Armazena em cache para possível reuso
        return data
    
    def export_data(self, format_type: str = 'json') -> str:
        """
        Exporta os dados coletados em diferentes formatos
        Parâmetros: json, csv (implementar outros se necessário)
        
        Útil para integração com outros sistemas ou para debug
        durante o desenvolvimento do SDK.
        """
        if not self.cache_data:
            self.collect_all_data()
        
        if format_type.lower() == 'json':
            return json.dumps(self.cache_data, indent=2, ensure_ascii=False)
        elif format_type.lower() == 'csv':
            # Implementação básica para CSV - pode ser expandida
            csv_lines = ["Category,Key,Value"]
            for category, data in self.cache_data.items():
                if isinstance(data, dict):
                    for key, value in data.items():
                        csv_lines.append(f"{category},{key},{value}")
                else:
                    csv_lines.append(f"{category},,{data}")
            
            return "\n".join(csv_lines)
        else:
            return "Formato não suportado"

# Teste
if __name__ == "__main__":
    # Inicializa o SDK
    sdk = DeviceEnvironmentSDK()
    
    # Coleta todos os dados
    print("Coletando dados do dispositivo e ambiente...")
    all_data = sdk.collect_all_data()
    
    # Exibe os dados em formato JSON
    print("\n=== DADOS COLETADOS ===")
    print(json.dumps(all_data, indent=2, ensure_ascii=False))
    
    # Exporta para diferentes formatos
    print("\n=== EXPORT JSON ===")
    print(sdk.export_data('json'))
    
    print("\n=== EXPORT CSV ===")
    print(sdk.export_data('csv'))