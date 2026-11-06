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

    // 4. Seleção e envio em lote para revisões de acessos (Fase 15.5)
    document.addEventListener('change', (e) => {
        if (e.target && e.target.classList && e.target.classList.contains('select-all-colab')) {
            const table = e.target.closest('table');
            if (table) {
                const checkboxes = table.querySelectorAll('.lote-checkbox');
                checkboxes.forEach((cb) => {
                    cb.checked = e.target.checked;
                });
            }
        }
    });

    document.addEventListener('submit', (e) => {
        const form = e.target;
        if (form && form.id === 'form-revisao-lote') {
            const checkboxes = document.querySelectorAll('.lote-checkbox:checked');
            if (checkboxes.length === 0) {
                alert('Selecione ao menos um acesso para aplicar a decisão em lote.');
                e.preventDefault();
                return;
            }
            const idsInput = form.querySelector('#lote_itens_ids');
            if (idsInput) {
                idsInput.value = Array.from(checkboxes)
                    .map((cb) => cb.value)
                    .join(',');
            }
        }
    });
});
