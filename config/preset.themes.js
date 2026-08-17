/**
 * The six built-in App Base themes as seedable token documents.
 * Values are extracted from web/src/styles/themes/*.css — the CSS files
 * remain the source of truth for the web app's own rendering; these documents
 * exist so presets are listable, forkable, and consumable by mobile.
 */

import Theme from '../models/theme.model.js';
import logger from '../utils/app.logger.js';

const preset = (name, slug, description, darkMode, colors, fonts, radii) => ({
    name,
    slug,
    description,
    isPreset: true,
    visibility: 'public',
    tokens: {darkMode, colors, fonts, radii}
});

const PRESET_THEMES = [
    preset('Modern', 'modern', 'Clean and professional design with modern aesthetics', false, {
        primary: '#12355B', primaryAccent: '#1A4A7A',
        secondary: '#FF570A', secondaryAccent: '#CC4000',
        tertiary: '#A5D8FF', tertiaryAccent: '#70BFFF',
        neutral: '#5A7A95', neutralAccent: '#3A5A75',
        success: '#1E7A3A', warning: '#E88500', error: '#CC2200',
        background: '#FFFFFF', surface: '#EAF5FF', surfaceAccent: '#C8EAFF',
        border: '#A5D8FF', text: '#12355B', textContrast: '#FFFFFF',
        shadow: 'rgba(18, 53, 91, 0.15)'
    }, {primary: 'urbanist', secondary: 'montserrat-alternates', monospace: 'jetbrains-mono'},
       {base: '0.375rem', card: '0.5rem', input: '0.375rem', button: '0.375rem', checkbox: '0.25rem', fab: '50%', progress: '9999px', notification: '0.5rem'}),

    preset('Dark', 'dark', 'Dark mode theme with high contrast and modern feel', true, {
        primary: '#A5D8FF', primaryAccent: '#70BFFF',
        secondary: '#FF570A', secondaryAccent: '#CC4000',
        tertiary: '#FFFFFF', tertiaryAccent: '#C8EAFF',
        neutral: '#4A7A9A', neutralAccent: '#2A5A7A',
        success: '#3ABC60', warning: '#FFB020', error: '#FF4444',
        background: '#0C2240', surface: '#12355B', surfaceAccent: '#1A4A7A',
        border: '#1A4A7A', text: '#EAF5FF', textContrast: '#0C2240',
        shadow: 'rgba(0, 0, 0, 0.3)'
    }, {primary: 'urbanist', secondary: 'montserrat-alternates', monospace: 'share-tech-mono'},
       {base: '0.5rem', card: '0.75rem', input: '0.375rem', button: '0.5rem', checkbox: '0.25rem', fab: '50%', progress: '0.25rem', notification: '0.5rem'}),

    preset('Minimal', 'minimal', 'Ultra-clean minimalist design with focus on content', false, {
        primary: '#374151', primaryAccent: '#111827',
        secondary: '#9CA3AF', secondaryAccent: '#4B5563',
        tertiary: '#4B5563', tertiaryAccent: '#374151',
        neutral: '#6B7280', neutralAccent: '#374151',
        success: '#047857', warning: '#D97706', error: '#B91C1C',
        background: '#F9FAFB', surface: '#E9E8E8', surfaceAccent: '#F3F4F6',
        border: '#E5E7EB', text: '#111827', textContrast: '#E9E8E8',
        shadow: 'rgba(55, 65, 81, 0.1)'
    }, {primary: 'advent-pro', secondary: 'syne-mono', monospace: 'nova-mono'},
       {base: '0', card: '0', input: '0', button: '0', checkbox: '0', fab: '0', progress: '0', notification: '0'}),

    preset('Vibrant', 'vibrant', 'Colorful and energetic design with bold styling', false, {
        primary: '#556303', primaryAccent: '#334200',
        secondary: '#BF3100', secondaryAccent: '#8E2400',
        tertiary: '#FF4E00', tertiaryAccent: '#CC3C00',
        neutral: '#8EA604', neutralAccent: '#6A7C02',
        success: '#8EA604', warning: '#EC9F05', error: '#BF3100',
        background: '#F5BB00', surface: '#FFF5CC', surfaceAccent: '#FEE870',
        border: '#8EA604', text: '#BF3100', textContrast: '#FFF5CC',
        shadow: 'rgba(191, 49, 0, 0.22)'
    }, {primary: 'gloria-hallelujah', secondary: 'bungee-spice', monospace: 'vt323'},
       {base: '1rem', card: '1.5rem', input: '0.75rem', button: '1rem', checkbox: '0.5rem', fab: '50%', progress: '9999px', notification: '1rem'}),

    preset('Admin', 'admin', 'Professional administrative interface design', true, {
        primary: '#EEC643', primaryAccent: '#F59E0B',
        secondary: '#FFFFFF', secondaryAccent: '#808080',
        tertiary: '#83C5BE', tertiaryAccent: '#006D77',
        neutral: '#A6A6A8', neutralAccent: '#CECECE',
        success: '#10B981', warning: '#FFC107', error: '#B42F2D',
        background: '#141414', surface: '#333333', surfaceAccent: '#444444',
        border: '#DEE2E6', text: '#96A2B0', textContrast: '#141414',
        shadow: 'rgba(161, 161, 161, 0.795)'
    }, {primary: 'jura', secondary: 'kode-mono', monospace: 'roboto-mono'},
       {base: '4px', card: '4px', input: '4px', button: '4px', checkbox: '2px', fab: '28px', progress: '2px', notification: '4px'}),

    preset('Pink', 'pink', 'Playful and vibrant design with a pink color palette', false, {
        primary: '#CC0C49', primaryAccent: '#A0003A',
        secondary: '#2E7D32', secondaryAccent: '#1B5E20',
        tertiary: '#7663F2', tertiaryAccent: '#5B4DC8',
        neutral: '#5C313E', neutralAccent: '#3E1828',
        success: '#2E7D32', warning: '#E65100', error: '#C62828',
        background: '#FDE8F0', surface: '#F9C8DA', surfaceAccent: '#F2A0BF',
        border: '#155946', text: '#6B0A2F', textContrast: '#FDE8F0',
        shadow: 'rgba(204, 12, 73, 0.2)'
    }, {primary: 'josefin-sans', secondary: 'borel', monospace: 'jetbrains-mono'},
       {base: '0.375rem', card: '0.5rem', input: '0.375rem', button: '0.375rem', checkbox: '0.25rem', fab: '50%', progress: '9999px', notification: '0.5rem'})
];

/** Upsert the six built-in presets (idempotent, runs at startup) */
export const seedPresetThemes = async () => {
    let created = 0;
    for (const doc of PRESET_THEMES) {
        const result = await Theme.updateOne(
            {slug: doc.slug, isPreset: true},
            {$setOnInsert: doc},
            {upsert: true}
        );
        if (result.upsertedCount > 0) created++;
    }
    if (created > 0) {
        logger.info(`🎨 Seeded ${created} preset theme(s)`);
    }
    return created;
};

export default PRESET_THEMES;
