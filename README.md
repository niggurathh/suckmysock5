# suckmysock5

Reverse SOCKS5 proxy ultra ligero con cifrado ChaCha20-Poly1305.

## Arquitectura

```
[Browser/App] → [SOCKS5:1080] → [Servidor] ══cifrado══► [Cliente] → [Internet]
                                     │                       │
                                  tu máquina            máquina remota
```

El **cliente** se conecta al servidor (conexión reversa). El **servidor** expone un puerto SOCKS5 local. Todo el tráfico viaja cifrado por el túnel.

## Compilación

### Requisitos
- Go 1.21+

### Compilar para tu plataforma
```bash
go build -o suckmysock5 .
```

### Compilar para todas las plataformas
```bash
make all
```

Genera binarios en `bin/`:
- `suckmysock5-linux-amd64`
- `suckmysock5-linux-386`
- `suckmysock5-windows-amd64.exe`
- `suckmysock5-windows-386.exe`
- `suckmysock5-darwin-amd64`
- `suckmysock5-darwin-arm64`

## Uso

### Servidor (tu máquina)
```bash
./suckmysock5 -listen :8443 -socks :1080 -key "mi-clave-secreta"
```

| Flag | Descripción |
|------|-------------|
| `-listen` | Puerto para conexiones del túnel |
| `-socks` | Puerto SOCKS5 local (default: 1080) |
| `-key` | Clave compartida para cifrado |

### Cliente (máquina remota)
```bash
./suckmysock5 -connect servidor.com:8443 -key "mi-clave-secreta"
```

| Flag | Descripción |
|------|-------------|
| `-connect` | Dirección del servidor |
| `-key` | Clave compartida (debe coincidir) |

### Usar el proxy
```bash
# curl
curl --socks5 127.0.0.1:1080 https://ifconfig.me

# proxychains
proxychains4 nmap -sT target.com

# Firefox/Chrome
Configurar proxy SOCKS5: 127.0.0.1:1080
```

## Ejemplo completo

```bash
# Terminal 1 - Servidor (tu máquina local)
./suckmysock5 -listen :8443 -socks :1080 -key secreto123

# Terminal 2 - Cliente (máquina remota con salida a internet)
./suckmysock5 -connect tu-ip:8443 -key secreto123

# Terminal 3 - Probar (desde tu máquina local)
curl --socks5 127.0.0.1:1080 https://ifconfig.me
# Debería mostrar la IP de la máquina remota
```

## Seguridad

- **Cifrado**: ChaCha20-Poly1305 (AEAD)
- **Derivación de clave**: Argon2id + HKDF
- **Nonce**: Incremental por conexión
- **Sin dependencias CGO**: Compila estáticamente

## Tamaño del binario

~2.0-2.3 MB (con `-ldflags="-s -w"`)
