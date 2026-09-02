import { useState, useEffect, useMemo, useCallback } from 'react';
import { Zap, AlertCircle, Plus } from 'lucide-react';
import { ScrollArea } from '../ui/scroll-area';
import { Card } from '../ui/card';
import { Button } from '../ui/button';
import { Switch } from '../ui/switch';
import { Skeleton } from '../ui/skeleton';
import { MainPanelLayout } from '../Layout/MainPanelLayout';
import { errorMessage } from '../../utils/conversionUtils';
import { getInitialWorkingDir } from '../../utils/workingDir';
import { defineMessages, useIntl } from '../../i18n';
import { SearchView } from '../conversation/SearchView';
import { getSearchShortcutText } from '../../utils/keyboardShortcuts';
import { listSkillSources } from '../../acp/sources';
import { useConfig } from '../ConfigContext';
import type { SourceType } from '@aaif/goose-sdk';

const DISABLED_SKILLS_KEY = 'DISABLED_SKILLS';

const i18n = defineMessages({
  errorLoadingSkills: {
    id: 'skillsView.errorLoadingSkills',
    defaultMessage: 'Error Loading Skills',
  },
  tryAgain: {
    id: 'skillsView.tryAgain',
    defaultMessage: 'Try Again',
  },
  noSkillsInstalled: {
    id: 'skillsView.noSkillsInstalled',
    defaultMessage: 'No skills installed',
  },
  noSkillsDescription: {
    id: 'skillsView.noSkillsDescription',
    defaultMessage:
      'Skills are loaded from SKILL.md files in ~/.config/agents/skills/, .goose/skills/, or other supported directories.',
  },
  noMatchingSkills: {
    id: 'skillsView.noMatchingSkills',
    defaultMessage: 'No matching skills found',
  },
  adjustSearchTerms: {
    id: 'skillsView.adjustSearchTerms',
    defaultMessage: 'Try adjusting your search terms',
  },
  skillsTitle: {
    id: 'skillsView.skillsTitle',
    defaultMessage: 'Skills',
  },
  addSkill: {
    id: 'skillsView.addSkill',
    defaultMessage: 'Add Skill',
  },
  skillsDescription: {
    id: 'skillsView.skillsDescription',
    defaultMessage:
      'Turn skills on or off for the model. Off skills stay listed here so you can turn them back on. {shortcut} to search.',
  },
  searchSkillsPlaceholder: {
    id: 'skillsView.searchSkillsPlaceholder',
    defaultMessage: 'Search skills...',
  },
  comingSoon: {
    id: 'skillsView.comingSoon',
    defaultMessage: 'Coming soon',
  },
  builtinBadge: {
    id: 'skillsView.builtinBadge',
    defaultMessage: 'Built-in',
  },
  toggleSkill: {
    id: 'skillsView.toggleSkill',
    defaultMessage: 'Turn {name} {state}',
  },
  toggleOn: {
    id: 'skillsView.toggleOn',
    defaultMessage: 'on',
  },
  toggleOff: {
    id: 'skillsView.toggleOff',
    defaultMessage: 'off',
  },
  toggleFailed: {
    id: 'skillsView.toggleFailed',
    defaultMessage: 'Could not update skill: {error}',
  },
});

interface SkillEntry {
  name: string;
  description: string;
  type: SourceType;
}

function disabledSkillNames(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((name): name is string => typeof name === 'string' && name.trim() !== '');
}

function SkillItem({
  skill,
  enabled,
  toggling,
  onToggle,
}: {
  skill: SkillEntry;
  enabled: boolean;
  toggling: boolean;
  onToggle: (name: string, enabled: boolean) => void;
}) {
  const intl = useIntl();
  const builtin = skill.type === 'builtinSkill';

  return (
    <Card className="py-2 px-4 mb-2 bg-background-primary border-none hover:bg-background-secondary transition-all duration-150">
      <div className="flex justify-between items-center gap-4">
        <div className={`min-w-0 flex-1 ${enabled ? '' : 'opacity-60'}`}>
          <div className="flex items-center gap-2 mb-1">
            <h3 className="text-base truncate">{skill.name}</h3>
            {builtin && (
              <span className="shrink-0 text-[10px] font-medium uppercase tracking-wide leading-none px-1.5 py-0.5 rounded-sm bg-background-warning text-black">
                {intl.formatMessage(i18n.builtinBadge)}
              </span>
            )}
          </div>
          <p className="text-text-secondary text-sm line-clamp-2">{skill.description}</p>
        </div>
        <Switch
          variant="mono"
          checked={enabled}
          disabled={toggling}
          onCheckedChange={(checked) => onToggle(skill.name, checked)}
          aria-label={intl.formatMessage(i18n.toggleSkill, {
            name: skill.name,
            state: enabled
              ? intl.formatMessage(i18n.toggleOff)
              : intl.formatMessage(i18n.toggleOn),
          })}
        />
      </div>
    </Card>
  );
}

function SkillSkeleton() {
  return (
    <Card className="p-2 mb-2 bg-background-primary">
      <div className="flex justify-between items-start gap-4">
        <div className="min-w-0 flex-1">
          <Skeleton className="h-5 w-3/4 mb-2" />
          <Skeleton className="h-4 w-full" />
        </div>
      </div>
    </Card>
  );
}

export default function SkillsView() {
  const intl = useIntl();
  const { config, upsert } = useConfig();
  const [skills, setSkills] = useState<SkillEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [showSkeleton, setShowSkeleton] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showContent, setShowContent] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [togglingName, setTogglingName] = useState<string | null>(null);

  const disabled = useMemo(
    () => new Set(disabledSkillNames(config[DISABLED_SKILLS_KEY])),
    [config]
  );

  const filteredSkills = useMemo(() => {
    if (!searchTerm) return skills;
    const searchLower = searchTerm.toLowerCase();
    return skills.filter(
      (skill) =>
        skill.name.toLowerCase().includes(searchLower) ||
        skill.description.toLowerCase().includes(searchLower)
    );
  }, [skills, searchTerm]);

  const loadSkills = useCallback(async () => {
    try {
      setLoading(true);
      setShowSkeleton(true);
      setShowContent(false);
      setError(null);
      const sources = await listSkillSources(getInitialWorkingDir());
      const skillEntries: SkillEntry[] = sources.map((source) => ({
        name: source.name,
        description: source.description,
        type: source.type,
      }));
      setSkills(skillEntries);
    } catch (err) {
      setError(errorMessage(err, 'Failed to load skills'));
    } finally {
      setLoading(false);
    }
  }, []);

  const handleToggle = async (name: string, enabled: boolean) => {
    const current = disabledSkillNames(config[DISABLED_SKILLS_KEY]);
    const next = enabled
      ? current.filter((skillName) => skillName !== name)
      : Array.from(new Set([...current, name]));
    setTogglingName(name);
    try {
      await upsert(DISABLED_SKILLS_KEY, next, false);
      setError(null);
    } catch (err) {
      setError(
        intl.formatMessage(i18n.toggleFailed, {
          error: errorMessage(err, 'unknown error'),
        })
      );
    } finally {
      setTogglingName(null);
    }
  };

  useEffect(() => {
    loadSkills();
  }, [loadSkills]);

  useEffect(() => {
    if (!loading && showSkeleton) {
      const timer = setTimeout(() => {
        setShowSkeleton(false);
        setTimeout(() => setShowContent(true), 50);
      }, 300);
      return () => clearTimeout(timer);
    }
    return undefined;
  }, [loading, showSkeleton]);

  const renderContent = () => {
    if (loading || showSkeleton) {
      return (
        <div className="space-y-2">
          <SkillSkeleton />
          <SkillSkeleton />
          <SkillSkeleton />
        </div>
      );
    }

    if (error && skills.length === 0) {
      return (
        <div className="flex flex-col items-center justify-center h-full text-text-secondary">
          <AlertCircle className="h-12 w-12 text-red-500 mb-4" />
          <p className="text-lg mb-2">{intl.formatMessage(i18n.errorLoadingSkills)}</p>
          <p className="text-sm text-center mb-4">{error}</p>
          <Button onClick={loadSkills} variant="default">
            {intl.formatMessage(i18n.tryAgain)}
          </Button>
        </div>
      );
    }

    if (skills.length === 0) {
      return (
        <div className="flex flex-col justify-center pt-2 h-full">
          <p className="text-lg">{intl.formatMessage(i18n.noSkillsInstalled)}</p>
          <p className="text-sm text-text-secondary">
            {intl.formatMessage(i18n.noSkillsDescription)}
          </p>
        </div>
      );
    }

    if (filteredSkills.length === 0 && searchTerm) {
      return (
        <div className="flex flex-col items-center justify-center h-full text-text-secondary mt-4">
          <Zap className="h-12 w-12 mb-4" />
          <p className="text-lg mb-2">{intl.formatMessage(i18n.noMatchingSkills)}</p>
          <p className="text-sm">{intl.formatMessage(i18n.adjustSearchTerms)}</p>
        </div>
      );
    }

    return (
      <div className="space-y-2">
        {error && <p className="text-sm text-red-600 dark:text-red-400 mb-2">{error}</p>}
        {filteredSkills.map((skill) => (
          <SkillItem
            key={`${skill.type}:${skill.name}`}
            skill={skill}
            enabled={!disabled.has(skill.name)}
            toggling={togglingName === skill.name}
            onToggle={(name, enabled) => void handleToggle(name, enabled)}
          />
        ))}
      </div>
    );
  };

  return (
    <MainPanelLayout>
      <div className="flex-1 flex flex-col min-h-0">
        <div className="bg-background-primary px-8 pb-8 pt-16">
          <div className="flex flex-col page-transition">
            <div className="flex justify-between items-center mb-1">
              <h1 className="text-4xl font-light">{intl.formatMessage(i18n.skillsTitle)}</h1>
              <Button
                variant="outline"
                size="sm"
                className="flex items-center gap-2"
                hidden
                title={intl.formatMessage(i18n.comingSoon)}
              >
                <Plus className="w-4 h-4" />
                {intl.formatMessage(i18n.addSkill)}
              </Button>
            </div>
            <p className="text-sm text-text-secondary mb-1">
              {intl.formatMessage(i18n.skillsDescription, {
                shortcut: getSearchShortcutText(),
              })}
            </p>
          </div>
        </div>

        <div className="flex-1 min-h-0 relative px-8">
          <ScrollArea className="h-full">
            <SearchView
              onSearch={(term) => setSearchTerm(term)}
              placeholder={intl.formatMessage(i18n.searchSkillsPlaceholder)}
            >
              <div
                className={`h-full relative transition-all duration-300 ${
                  showContent || showSkeleton ? 'opacity-100 animate-in fade-in' : 'opacity-0'
                }`}
              >
                {renderContent()}
              </div>
            </SearchView>
          </ScrollArea>
        </div>
      </div>
    </MainPanelLayout>
  );
}
