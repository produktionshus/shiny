// Regenerates extras.json: costumes are pulled from the live game master,
// regionals/specials are curated lists kept here. Run: node gen_extras.js
const fs = require('fs');
const GM = 'https://raw.githubusercontent.com/PokeMiners/game_masters/master/latest/latest.json';

const title = s => s.toLowerCase().replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

// editorial list — current GO regional exclusives
const REGIONALS = [
  [83, "Farfetch'd", 'East Asia'], [115, 'Kangaskhan', 'Australia'],
  [122, 'Mr. Mime', 'Europe'], [128, 'Tauros', 'The Americas'],
  [214, 'Heracross', 'Latin America'], [222, 'Corsola', 'Tropics'],
  [324, 'Torkoal', 'South Asia'], [335, 'Zangoose', 'Rotating hemisphere'],
  [336, 'Seviper', 'Rotating hemisphere'], [337, 'Lunatone', 'Rotating hemisphere'],
  [338, 'Solrock', 'Rotating hemisphere'], [357, 'Tropius', 'Africa/Mediterranean'],
  [369, 'Relicanth', 'New Zealand/Pacific'], [417, 'Pachirisu', 'Canada/Russia/Alaska'],
  [441, 'Chatot', 'Southern Hemisphere'], [455, 'Carnivine', 'Southeast US'],
  [480, 'Uxie', 'Asia-Pacific'], [481, 'Mesprit', 'Europe/Africa/Middle East'],
  [482, 'Azelf', 'The Americas/Greenland'], [538, 'Throh', 'Americas/Africa'],
  [539, 'Sawk', 'Europe/Asia-Pacific'], [550, 'Basculin', 'Stripe by hemisphere'],
  [556, 'Maractus', 'Southern US/Latin America'], [561, 'Sigilyph', 'Egypt/Greece'],
  [626, 'Bouffalant', 'New York area'], [631, 'Heatmor', 'Western Hemisphere'],
  [632, 'Durant', 'Eastern Hemisphere'], [666, 'Vivillon', 'Patterns by region'],
  [701, 'Hawlucha', 'Mexico'], [707, 'Klefki', 'France'],
  [741, 'Oricorio', 'Style by region'], [764, 'Comfey', 'Hawaii'],
  [774, 'Minior', 'Core colours rotate'], [874, 'Stonjourner', 'UK/Ireland (events)'],
].map(([dex, name, region]) => ({ key: `r${dex}`, dex, name, sub: region }));

// legendary & mythical exceptions: unique event forms and research-exclusives
const SPECIALS = [
  { key: 's150_A', dex: 150, name: 'Armored Mewtwo', sub: 'Raid event exclusive form', form: 'A' },
  { key: 's151', dex: 151, name: 'Mew', sub: 'Special Research (A Mythical Discovery)' },
  { key: 's251', dex: 251, name: 'Celebi', sub: 'Special Research (A Ripple in Time)' },
  { key: 's385', dex: 385, name: 'Jirachi', sub: 'Special Research (A Thousand-Year Slumber)' },
  { key: 's386', dex: 386, name: 'Deoxys', sub: 'EX/regular raids, four forms' },
  { key: 's491', dex: 491, name: 'Darkrai', sub: 'Halloween raids' },
  { key: 's492', dex: 492, name: 'Shaymin', sub: 'GO Fest research, Land/Sky forms' },
  { key: 's494', dex: 494, name: 'Victini', sub: 'Special Research (The Feeling of Victory)' },
  { key: 's647', dex: 647, name: 'Keldeo', sub: 'Special Research (Something Extraordinary)' },
  { key: 's648', dex: 648, name: 'Meloetta', sub: 'GO Fest Special Research' },
  { key: 's649', dex: 649, name: 'Genesect', sub: 'Special Research + raids, drive forms' },
  { key: 's718', dex: 718, name: 'Zygarde', sub: 'Routes (From A to Zygarde), three forms' },
  { key: 's719', dex: 719, name: 'Diancie', sub: 'GO Fest Special Research' },
  { key: 's720', dex: 720, name: 'Hoopa', sub: 'Misunderstood Mischief research, two forms' },
  { key: 's800', dex: 800, name: 'Necrozma', sub: 'GO Fest raids, fusion forms' },
  { key: 's802', dex: 802, name: 'Marshadow', sub: 'GO Fest Special Research' },
  { key: 's891', dex: 891, name: 'Kubfu', sub: 'Special Research (To Be a Better Buddy)' },
  { key: 's893', dex: 893, name: 'Zarude', sub: 'Special Research (Search for Zarude)' },
];

(async () => {
  console.log('Fetching game master…');
  const gm = await (await fetch(GM)).json();
  const costumes = [];
  for (const e of gm) {
    const fset = e.data && e.data.formSettings;
    if (!fset || !fset.forms) continue;
    const m = e.templateId.match(/^FORMS_V(\d{4})_POKEMON_/);
    if (!m) continue;
    const dex = +m[1];
    const base = fset.pokemon;
    for (const f of fset.forms) {
      if (!f.isCostume || !f.form) continue;
      const suffix = f.form.startsWith(base + '_') ? f.form.slice(base.length + 1) : f.form;
      costumes.push({
        key: `c${dex}_${suffix}`,
        dex,
        name: title(base),
        sub: title(suffix),
        form: suffix,
      });
    }
  }
  costumes.sort((a, b) => a.dex - b.dex || a.form.localeCompare(b.form));
  const out = {
    generated: new Date().toISOString().slice(0, 10),
    costumes,
    regionals: REGIONALS,
    specials: SPECIALS,
  };
  fs.writeFileSync(require('path').join(__dirname, 'extras.json'), JSON.stringify(out, null, 1));
  console.log(`extras.json written: ${costumes.length} costumes, ${REGIONALS.length} regionals, ${SPECIALS.length} specials`);
})();
