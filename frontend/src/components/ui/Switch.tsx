import React from 'react';
import clsx from 'clsx';
import './Switch.css';

interface SwitchProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: string;
  disabled?: boolean;
  size?: 'xxs' | 'xs' | 'sm' | 'md';
  className?: string;
}

export default function Switch({
  checked,
  onChange,
  label,
  disabled = false,
  size = 'md',
  className,
}: SwitchProps) {
  return (
    <label className={clsx('switch-container', className)}>
      <input
        type="checkbox"
        className="switch-input"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        disabled={disabled}
      />
      <span className={clsx('switch', `switch-${size}`, { 'switch-disabled': disabled })}>
        <span className="switch-thumb" />
      </span>
      {label && <span className="switch-label">{label}</span>}
    </label>
  );
}
