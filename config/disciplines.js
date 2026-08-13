/**
 * Creative discipline taxonomy
 *
 * Used for profile tags, work classification, discovery filters, and search facets.
 * Keys are stable identifiers (stored in the DB); labels are for display.
 * Each discipline lists the media block types most natural to it — the studio UI
 * uses this to pre-select upload flows, but any work can use any block type.
 */

export const MEDIA_BLOCK_TYPES = [
    'image',        // Image component (single or set)
    'video',        // Video component
    'audio',        // Audio component (waveform)
    'model3d',      // Model3D component (glb/gltf/obj/stl/fbx/ply/dae/3mf/vox/3ds)
    'document',     // PdfViewer component
    'writing',      // Editor (tiptap) content, rendered read-only
    'flow',         // Flow component (process graphs, moodboards)
    'embed'         // External embed (kept allowlisted)
];

export const DISCIPLINES = {
    ILLUSTRATION:     {label: 'Illustration',            defaultBlocks: ['image']},
    GRAPHIC_DESIGN:   {label: 'Graphic Design',          defaultBlocks: ['image', 'document']},
    UI_UX:            {label: 'UI / UX Design',          defaultBlocks: ['image', 'video', 'flow']},
    PHOTOGRAPHY:      {label: 'Photography',             defaultBlocks: ['image']},
    THREE_D:          {label: '3D Art & Modeling',       defaultBlocks: ['model3d', 'image', 'video']},
    FASHION:          {label: 'Fashion & Garment',       defaultBlocks: ['image', 'model3d', 'document']},
    ANIMATION:        {label: 'Animation & Motion',      defaultBlocks: ['video', 'image']},
    FILM:             {label: 'Film & Video',            defaultBlocks: ['video']},
    MUSIC:            {label: 'Music & Sound',           defaultBlocks: ['audio', 'video']},
    WRITING:          {label: 'Writing & Publishing',    defaultBlocks: ['writing', 'document']},
    CRAFT:            {label: 'Craft & Handmade',        defaultBlocks: ['image', 'video']},
    ARCHITECTURE:     {label: 'Architecture & Interior', defaultBlocks: ['image', 'model3d', 'document']},
    GAME_ART:         {label: 'Game Art & Dev',          defaultBlocks: ['model3d', 'image', 'video']},
    MIXED_MEDIA:      {label: 'Mixed Media',             defaultBlocks: ['image']}
};

export const DISCIPLINE_KEYS = Object.keys(DISCIPLINES);

/**
 * Check that every entry of a list is a known discipline key
 * @param {Array<String>} keys
 * @returns {Boolean}
 */
export const areValidDisciplines = (keys) => {
    if (!Array.isArray(keys)) return false;
    return keys.every((key) => DISCIPLINE_KEYS.includes(key));
};
