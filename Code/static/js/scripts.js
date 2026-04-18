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
// Agregar clase two-col a grupos con más de 5 opciones
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.option-group').forEach(function(group) {
        if (group.children.length > 5) group.classList.add('two-col');
    });
    
    // Inicializar toggleOptions si existe
    if (document.getElementById('question_type')) {
        toggleOptions();
    }
});