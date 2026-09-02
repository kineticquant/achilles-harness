import { Select } from '../ui/Select';
import { fileOptionLabel, groupFilesByFolder, type FileOption } from '../../codeMap/groupFiles';

export default function CodeMapFileSelect({
  files,
  value,
  onChange,
  placeholder,
  allLabel,
}: {
  files: string[];
  value: string;
  onChange: (file: string) => void;
  placeholder: string;
  allLabel: string;
}) {
  const grouped = groupFilesByFolder(files);
  const options = [{ label: allLabel, options: [{ value: '', label: allLabel }] }, ...grouped];
  const selected = value
    ? { value, label: fileOptionLabel(value) }
    : { value: '', label: allLabel };

  return (
    <Select
      isSearchable
      isClearable
      placeholder={placeholder}
      value={selected}
      options={options}
      onChange={(option) => {
        const next = option as FileOption | null;
        onChange(next?.value ?? '');
      }}
      filterOption={(option, raw) => {
        const q = raw.trim().toLowerCase();
        if (!q) return true;
        const data = option.data as FileOption;
        return (
          data.value.toLowerCase().includes(q) ||
          data.label.toLowerCase().includes(q) ||
          allLabel.toLowerCase().includes(q)
        );
      }}
      formatGroupLabel={(group) =>
        group.label === allLabel ? (
          <span className="text-[10px] uppercase tracking-wide text-text-tertiary">{group.label}</span>
        ) : (
          <span className="font-mono text-[10px] uppercase tracking-wide text-text-tertiary">
            {group.label}
          </span>
        )
      }
      menuPortalTarget={typeof document === 'undefined' ? undefined : document.body}
      menuPosition="fixed"
      className="min-w-0"
    />
  );
}
