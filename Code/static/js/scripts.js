// Función para redirigir a otra ruta
function redirect(route) {
    window.location.href = route;
}

// ==================== Survey Functions ====================

// Mostrar/ocultar opciones según tipo de pregunta
function toggleOptions() {
    const type = document.getElementById('question_type').value;
    document.getElementById('options-group').style.display =
        (type === 's' || type === 'm') ? 'block' : 'none';
}

// Agregar opción a la pregunta
function addOption() {
    const container = document.getElementById('options-container');
    const input = document.createElement('input');
    input.type = 'text';
    input.name = 'options[]';
    input.className = 'option-input';
    input.placeholder = `Opción ${container.children.length + 1}`;
    input.style.marginTop = '6px';
    container.appendChild(input);
    refreshOptionsLayout(container);
}

// Ajustar layout de opciones
function refreshOptionsLayout(container) {
    const count = container.children.length;
    if (count > 5) {
        container.style.display = 'grid';
        container.style.gridTemplateColumns = '1fr 1fr';
        container.style.gap = '6px';
    } else {
        container.style.display = 'block';
    }
}

// Alternar entre pregunta demográfica y no demográfica
function toggleRequired(demoCheckId, requiredGroupId) {
    const isDemo = document.getElementById(demoCheckId).checked;
    const group  = document.getElementById(requiredGroupId);
    if (isDemo) {
        group.style.display = 'none';
        const reqBox = group.querySelector('input[type="checkbox"]');
        if (reqBox) reqBox.checked = true;
    } else {
        group.style.display = 'inline';
    }
}

// Mostrar/ocultar formulario de edición de pregunta
function toggleEditQuestion(questionId) {
    const editForm = document.getElementById(`edit-form-${questionId}`);
    const isHidden = editForm.style.display === 'none';
    editForm.style.display = isHidden ? 'block' : 'none';
    editForm.classList.toggle('show', isHidden);
}

// Mostrar/ocultar opciones en la edición
function toggleEditOptions(questionId) {
    const type = document.getElementById(`edit-type-${questionId}`).value;
    document.getElementById(`edit-options-group-${questionId}`).style.display =
        (type === 's' || type === 'm') ? 'block' : 'none';
}

// Agregar opción en la edición
function addEditOption(questionId) {
    const container = document.getElementById(`edit-options-container-${questionId}`);
    const div = document.createElement('div');
    div.style.cssText = 'display:flex; gap:8px; margin-bottom:8px;';

    const input = document.createElement('input');
    input.type = 'text';
    input.name = 'edit_options[]';
    input.className = 'option-input';
    input.placeholder = `Opción ${container.children.length + 1}`;
    input.style.flexGrow = '1';

    const hidden = document.createElement('input');
    hidden.type = 'hidden';
    hidden.name = 'edit_option_ids[]';
    hidden.value = '';

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'secondary';
    btn.textContent = '✕';
    btn.style.width = 'auto';
    btn.onclick = function() { removeEditOption(this); };

    div.appendChild(input);
    div.appendChild(hidden);
    div.appendChild(btn);
    container.appendChild(div);
    refreshOptionsLayout(container);
}

// Eliminar opción en la edición
function removeEditOption(button) {
    button.parentElement.remove();
}

// Validar que el título de la encuesta no esté vacío
function validateTitle() {
    const title = document.getElementById('survey_title').value.trim();
    if (!title) { 
        alert('El título de la encuesta es obligatorio.'); 
        return false; 
    }
    return true;
}

// Validar que el título de la pregunta no esté vacío
function validateQuestionTitle() {
    const title = document.getElementById('question_title').value.trim();
    if (!title) { 
        alert('El título de la pregunta es obligatorio.'); 
        return false; 
    }
    return true;
}

// ==================== Drag & Drop ====================
let draggedElement = null;

document.addEventListener('dragstart', function(e) {
    if (e.target.classList.contains('question-item')) {
        draggedElement = e.target;
        e.target.style.opacity = '0.5';
        e.dataTransfer.effectAllowed = 'move';
    }
});

document.addEventListener('dragover', function(e) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    const afterElement = getDragAfterElement(e.clientY);
    const container = document.getElementById('questions-container');
    if (!container) return;
    if (afterElement == null) container.appendChild(draggedElement);
    else container.insertBefore(draggedElement, afterElement);
});

document.addEventListener('dragend', function(e) {
    if (e.target.classList.contains('question-item')) {
        e.target.style.opacity = '1';
        draggedElement = null;
        saveQuestionOrder();
    }
});

// Obtener el elemento después del cual insertar
function getDragAfterElement(y) {
    const els = Array.from(document.querySelectorAll('.question-item:not([style*="opacity: 0.5"])'));
    return els.reduce((closest, child) => {
        const box = child.getBoundingClientRect();
        const offset = y - box.top - box.height / 2;
        return (offset < 0 && offset > closest.offset)
            ? { offset, element: child }
            : closest;
    }, { offset: Number.NEGATIVE_INFINITY }).element;
}

// Guardar el nuevo orden de preguntas
function saveQuestionOrder() {
    const container = document.getElementById('questions-container');
    if (!container) return;
    const ids = Array.from(container.querySelectorAll('.question-item'))
        .map(el => el.getAttribute('data-question-id'));
    if (!ids.length) return;
    const form = document.createElement('form');
    form.method = 'POST';
    form.innerHTML = `
        <input type="hidden" name="reorder_questions" value="true">
        <input type="hidden" name="question_order" value="${ids.join(',')}">`;
    document.body.appendChild(form);
    form.submit();
}

// ==================== Vote Survey ====================
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.option-group').forEach(function(group) {
        if (group.children.length > 5) group.classList.add('two-col');
    });
    
    // Inicializar toggleOptions si existe
    if (document.getElementById('question_type')) {
        toggleOptions();
    }
});

/* ═══════════════════════════════════════════════════════════════════════════════ */
/* ESTADÍSTICAS – Statistics Functions */
/* ═══════════════════════════════════════════════════════════════════════════════ */

// Variables globales para estadísticas (se definen en el template)
// const submissions   = {{ submissions_json | safe }};
// const demoFilters   = {{ demo_filters_json | safe }};
// const questionsMeta = {{ questions_meta_json | safe }};

function initializeStats(submissions, demoFilters, questionsMeta) {
    // Estado de filtros: { qid: Set | {min,max} }
    window.filterState = {};

    /* ── Construir filtros ── */
    function buildFilters() {
        const section = document.getElementById('filter-section');
        if (!section) return;
        const grid    = document.getElementById('filter-grid');
        if (!demoFilters.length) return;
        section.style.display = '';

        demoFilters.forEach(f => {
            const card = document.createElement('div');
            card.className = 'filter-card';
            card.innerHTML = `<h4>${escHtml(f.title)}</h4><div id="fc-${f.id}"></div>`;
            grid.appendChild(card);
            const container = document.getElementById(`fc-${f.id}`);

            if (f.type === 't') {
                // Searchable multi-select
                window.filterState[f.id] = new Set();
                container.innerHTML = `
                    <input class="filter-search" type="text"
                        placeholder="Buscar..."
                        oninput="filterSearch('${f.id}', this.value)">
                    <div class="filter-list" id="fl-${f.id}"></div>`;
                renderTextOptions(f.id, f.values, '');

            } else if (f.type === 'n') {
                // Rango numérico
                window.filterState[f.id] = { min: null, max: null };
                container.innerHTML = `
                    <div class="range-inputs">
                        <input type="number" placeholder="${f.min}" step="any"
                            oninput="updateRange('${f.id}','min',this.value)">
                        <span class="range-sep">≤ x ≤</span>
                        <input type="number" placeholder="${f.max}" step="any"
                            oninput="updateRange('${f.id}','max',this.value)">
                    </div>
                    <div class="range-hint">Rango disponible: ${f.min} – ${f.max}</div>`;

            } else {
                // S/M sin búsqueda
                window.filterState[f.id] = new Set();
                const list = document.createElement('div');
                list.className = 'filter-list';
                list.id = `fl-${f.id}`;
                container.appendChild(list);
                f.options.forEach(o => {
                    const item = makeCheckItem(String(o.id), o.text, f.id);
                    list.appendChild(item);
                });
            }
        });
    }

    function renderTextOptions(fid, values, search) {
        const list = document.getElementById(`fl-${fid}`);
        list.innerHTML = '';
        const lower = search.toLowerCase();
        values
            .filter(v => v.toLowerCase().includes(lower))
            .forEach(v => {
                const item = makeCheckItem(v, v, fid);
                // restore checked state
                if (window.filterState[fid].has(v)) item.querySelector('input').checked = true;
                list.appendChild(item);
            });
    }

    function filterSearch(fid, val) {
        const f = demoFilters.find(x => x.id === fid);
        renderTextOptions(fid, f.values, val);
    }

    function makeCheckItem(value, label, fid) {
        const div = document.createElement('div');
        div.className = 'filter-item';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.value = value;
        cb.checked = window.filterState[fid].has(value);
        cb.onchange = () => {
            if (cb.checked) window.filterState[fid].add(value);
            else window.filterState[fid].delete(value);
            renderStats();
        };
        const lbl = document.createElement('label');
        lbl.textContent = label;
        lbl.style.cursor = 'pointer';
        lbl.onclick = () => { cb.click(); };
        div.appendChild(cb);
        div.appendChild(lbl);
        return div;
    }

    function updateRange(fid, key, val) {
        window.filterState[fid][key] = val === '' ? null : parseFloat(val);
        renderStats();
    }

    function resetFilters() {
        demoFilters.forEach(f => {
            if (f.type === 'n') {
                window.filterState[f.id] = { min: null, max: null };
                document.querySelectorAll(`#fc-${f.id} input[type=number]`).forEach(i => i.value = '');
            } else {
                window.filterState[f.id] = new Set();
                document.querySelectorAll(`#fc-${f.id} input[type=checkbox]`).forEach(i => i.checked = false);
            }
        });
        renderStats();
    }

    /* ── Filtrado ── */
    function getFiltered() {
        return submissions.filter(sub => {
            for (const f of demoFilters) {
                const state = window.filterState[f.id];
                const answers = sub.answers[f.id] || [];

                if (f.type === 'n') {
                    if (state.min === null && state.max === null) continue;
                    const val = parseFloat(answers[0]);
                    if (isNaN(val)) return false;
                    if (state.min !== null && val < state.min) return false;
                    if (state.max !== null && val > state.max) return false;
                } else {
                    // Set vacío = sin filtro
                    if (state.size === 0) continue;
                    const hasMatch = answers.some(a => state.has(String(a)));
                    if (!hasMatch) return false;
                }
            }
            return true;
        });
    }

    /* ── Render estadísticas ── */
    function renderStats() {
        const filtered = getFiltered();
        const filteredCountEl = document.getElementById('filtered-count');
        if (filteredCountEl) filteredCountEl.textContent = filtered.length;

        const container = document.getElementById('stats-container');
        if (!container) return;
        
        if (!questionsMeta.length) {
            container.innerHTML = '<p class="no-data">No hay preguntas de resultado.</p>';
            return;
        }

        container.innerHTML = questionsMeta.map((q, idx) => {
            let body = '';

            if (q.type === 's' || q.type === 'm') {
                const counts = {};
                q.options.forEach(o => counts[o.id] = 0);
                filtered.forEach(sub => {
                    (sub.answers[q.id] || []).forEach(optId => {
                        if (counts.hasOwnProperty(optId)) counts[optId]++;
                    });
                });
                const total = filtered.length || 1;
                body = q.options.map(o => {
                    const cnt = counts[o.id] || 0;
                    const pct = total > 0 ? (cnt / total * 100).toFixed(1) : '0.0';
                    return `<div class="bar-row">
                        <span class="bar-label">${escHtml(o.text)}</span>
                        <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
                        <span class="bar-count">${cnt} <span style="color:#aaa;font-weight:400">(${pct}%)</span></span>
                    </div>`;
                }).join('');

            } else if (q.type === 'n') {
                const vals = [];
                filtered.forEach(sub => {
                    (sub.answers[q.id] || []).forEach(v => {
                        const n = parseFloat(v);
                        if (!isNaN(n)) vals.push(n);
                    });
                });
                const sum = vals.reduce((a, b) => a + b, 0);
                const avg = vals.length ? sum / vals.length : 0;
                body = `<div class="num-box">
                    <div class="num-stat"><div class="val">${vals.length}</div><div class="lbl">Respuestas</div></div>
                    <div class="num-stat"><div class="val">${fmt(sum)}</div><div class="lbl">Suma</div></div>
                    <div class="num-stat"><div class="val">${fmt(avg)}</div><div class="lbl">Media</div></div>
                </div>`;

            } else if (q.type === 't') {
                const count = filtered.filter(s => (s.answers[q.id] || []).length > 0).length;
                body = `<div class="text-private">
                    🔒 Pregunta de texto libre — ${count} respuesta${count !== 1 ? 's' : ''} recibida${count !== 1 ? 's' : ''}.
                    El contenido no se muestra para preservar la privacidad.
                </div>`;
            }

            return `<div class="stats-card">
                <h3>#${idx + 1} — ${escHtml(q.title)}</h3>
                ${body || '<p class="no-data">Sin datos para esta selección.</p>'}
            </div>`;
        }).join('');
    }

    // Exponer funciones globales
    window.filterSearch = filterSearch;
    window.updateRange = updateRange;
    window.resetFilters = resetFilters;

    buildFilters();
    renderStats();
}

function fmt(n) {
    const f = parseFloat(n);
    if (isNaN(f)) return '—';
    return Number.isInteger(f) ? f : f.toFixed(2);
}

function escHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}