/**
 * GateKeeper-DBF - Scripts Utilitários Globais
 * Desacoplamento de JavaScript para conformidade com CSP estrita (Fases 0.4 e 2.3)
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Inicializa ícones Lucide de forma limpa e sem inline scripts
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }

    // 2. Interceptador global para botões de submissão com confirmação data-confirm
    document.addEventListener('submit', (e) => {
        const submitter = e.submitter;
        if (submitter && submitter.dataset && submitter.dataset.confirm) {
            if (!confirm(submitter.dataset.confirm)) {
                e.preventDefault();
            }
        }
    });

    // 3. Interceptador para botões de impressão (data-action="print")
    document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-action="print"]');
        if (target) {
            e.preventDefault();
            window.print();
        }
    });
});
