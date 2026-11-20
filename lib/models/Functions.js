const mongoose = require('mongoose')

const functionsSchema = mongoose.Schema({
    name:           { type: String, required: true, trim: true, unique: true },
    description:    { type: String, trim: true },
    _permissions:   [ { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'Permission' } ],
    _menus:         [ { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'Menu' } ],
    // Opcional: un "role" se arma marcando otras funciones en _functions, y sus _permissions/_menus
    // se calculan como la unión de las de esas funciones. Por defecto todo es "capability", así que
    // los proyectos que no usen roles siguen funcionando igual que siempre.
    kind:           { type: String, enum: ['capability','role'], default: 'capability' },
    // Marca de acceso total. Antes el propietario se reconocía por el NOMBRE de la función
    // ("Propietario"), así que ningún rol nuevo podía sustituirlo por más funciones que tuviera.
    // Con esta bandera el nombre deja de decidir la autorización.
    isOwner:        { type: Boolean, default: false },
    _functions:     [ { type: mongoose.Schema.Types.ObjectId, ref: 'Functions' } ],
    data:           { type: Object, default: {} },
    status:         { type: String, required: true, enum: ['Activo','Inactivo'] },
    createdAt:      { type: Number },
    lastUpdate:     { type: Number }
})

const Functions = mongoose.model("Functions", functionsSchema)
module.exports = Functions