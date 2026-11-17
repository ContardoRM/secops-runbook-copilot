---
id: activate-fixed-kernel
asset_id: secops-kernel-lab
approval_required: true
---

# Activar el kernel corregido

## Precondiciones
- VM de laboratorio secops-kernel-lab.
- Kernel activo: 7.0.0-1012-oracle.
- Paquete instalado:
  linux-image-7.0.0-1013-oracle, versión 7.0.0-1013.13~24.04.1.
- Entrada del kernel corregido presente en GRUB.
- Aprobación humana explícita para interrumpir la VM.

## Procedimiento
1. Guardar evidencia y el identificador del arranque actual.
2. Seleccionar explícitamente el kernel 1013 para el próximo arranque.
3. Comprobar la selección antes de reiniciar.
4. Solicitar el reinicio.
5. Esperar la reconexión SSH con un plazo limitado.
6. Confirmar que cambió el identificador de arranque.
7. Recoger nuevamente el inventario y evaluar el kernel activo.

## Éxito
- SSH vuelve a estar disponible.
- Kernel activo: 7.0.0-1013-oracle.
- Evaluación: fixed_kernel_active_for_lab_case.

## Fallo
Si no vuelve SSH o arranca otro kernel, registrar fallo y solicitar
intervención mediante la consola de Oracle. No repetir reinicios.

## Limitaciones
La validación corresponde únicamente a este caso del laboratorio.
No demuestra ausencia de otras vulnerabilidades ni explotación.
No instalar paquetes ni eliminar kernels.

## Fuente
https://ubuntu.com/security/CVE-2026-92502
