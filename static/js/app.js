/**
 * GateKeeper-DBF - Scripts Utilitários Globais
 * Desacoplamento de JavaScript para conformidade com CSP (Fase 0.4)
 */

document.addEventListener('DOMContentLoaded', () => {
    // Interceptador global para botões de submissão com confirmação data-confirm
    document.addEventListener('submit', (e) => {
        const submitter = e.submitter;
        if (submitter && submitter.dataset && submitter.dataset.confirm) {
            if (!confirm(submitter.dataset.confirm)) {
                e.preventDefault();
            }
        }
    });
});

