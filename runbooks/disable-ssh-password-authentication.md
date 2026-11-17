---
id: disable-ssh-password-authentication
asset_id: ssh-vulnerable
approval_required: true
---

# Mitigar autenticación SSH por contraseña

## Objetivo
Deshabilitar la autenticación por contraseña en el contenedor de laboratorio.

## Precondiciones
- Evaluación reciente: exposure_conditions_present.
- Contenedor: ssh-vulnerable.
- Acceso administrativo disponible mediante Docker desde VM2.
- Aprobación humana registrada.
- No modificar el SSH del host Ubuntu.

## Procedimiento
1. Guardar una copia de /etc/ssh/sshd_config fuera del contenedor.
2. Cambiar PasswordAuthentication a no.
3. Validar la configuración con sshd -t.
4. Si la validación falla, restaurar la configuración y detener el procedimiento.
5. Reiniciar el contenedor para reemplazar el proceso SSH.
6. Volver a recolectar el inventario y ejecutar el evaluador.

## Criterios de éxito
- Contenedor en ejecución.
- Configuración efectiva: PasswordAuthentication no.
- Evaluación: password_authentication_mitigated.

## Recuperación
Restaurar la configuración guardada, validarla y reiniciar el contenedor.
Si no se recupera, registrar el fallo y solicitar intervención.

## Limitaciones
Esta mitigación no instala el parche.
Sin claves configuradas, labuser no podrá entrar por SSH.
El acceso administrativo mediante Docker permanece disponible.
El cambio no sobrevive a recrear el contenedor desde la imagen original.
La corrección permanente requiere reconstruir la imagen y verificarla.

## Fuente
https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/
